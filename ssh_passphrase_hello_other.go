//go:build !windows

// ssh_passphrase_hello_other.go — the non-Windows counterpart of the Windows
// Hello consent gate. There is no biometric prompt to surface, so consent is a
// no-op and the credential vault's own protection applies. This keeps
// ssh_passphrase.go cross-platform (it builds and runs on the maintainer's macOS
// / Linux host) without a separate build matrix.
package main

// requestUserConsent is a no-op off Windows: there is no Windows Hello prompt to
// raise, and the host vault gates the read on its own.
func requestUserConsent(reason string) error {
	_ = reason
	return nil
}
