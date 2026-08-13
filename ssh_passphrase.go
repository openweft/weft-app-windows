// ssh_passphrase.go — the SSH key-passphrase store, backed by the host
// credential vault through the go-keyring/keyring façade (see vault.go). It uses
// a Credential Manager service prefix ("weft-ssh-passphrase") separate from the
// session-token store (keychain.go) so removing one does not affect the other.
//
// On Windows the passphrase items live in the Credential Manager, itself
// encrypted with the account's DPAPI master key; the read is additionally gated
// by Windows Hello when the machine is enrolled (see requestUserConsent in
// ssh_passphrase_hello_windows.go). On other platforms requestUserConsent is a
// no-op and the vault's own protection applies.
package main

import (
	"errors"
	"fmt"
)

// sshPassphraseService is the vault service every passphrase entry is filed
// under; the per-key account is the canonical SSH key file path.
const sshPassphraseService = "weft-ssh-passphrase"

// consentFn is the Windows Hello consent gate, kept as a seam so tests can
// exercise the cancel path. It defaults to the per-platform requestUserConsent
// (the WinRT prompt on Windows, a no-op elsewhere).
var consentFn = requestUserConsent

// sshPassphraseGet returns the passphrase stored for keyPath, or nil when no
// entry exists (the caller can then prompt via --store-ssh-passphrase). On a
// Windows Hello-enrolled machine the user is asked to confirm biometry first;
// the step is skipped when the machine is not enrolled.
func sshPassphraseGet(keyPath string) ([]byte, error) {
	if err := consentFn("Unlock your SSH key passphrase to connect to the Weft cluster"); err != nil {
		return nil, fmt.Errorf("windows hello: %w", err)
	}
	blob, err := vaultGet(sshPassphraseService, keyPath)
	switch {
	case errors.Is(err, errVaultNotFound), errors.Is(err, errVaultUnavailable):
		return nil, nil
	case err != nil:
		return nil, fmt.Errorf("credential vault get (service=%s account=%s): %w", sshPassphraseService, keyPath, err)
	}
	return blob, nil
}

// sshPassphraseSet stores or replaces the passphrase for keyPath.
func sshPassphraseSet(keyPath string, passphrase []byte) error {
	if err := vaultSet(sshPassphraseService, keyPath, passphrase); err != nil {
		return fmt.Errorf("credential vault set (service=%s account=%s): %w", sshPassphraseService, keyPath, err)
	}
	return nil
}

// sshPassphraseDelete removes the passphrase entry for keyPath (no-op when
// nothing is cached).
func sshPassphraseDelete(keyPath string) error {
	if err := vaultDelete(sshPassphraseService, keyPath); err != nil {
		return fmt.Errorf("credential vault delete (service=%s account=%s): %w", sshPassphraseService, keyPath, err)
	}
	return nil
}
