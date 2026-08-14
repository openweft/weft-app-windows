//go:build windows

// ssh_passphrase_hello_windows.go — the Windows Hello (WinRT
// UserConsentVerifier) gate layered on top of the passphrase read in
// ssh_passphrase.go. The WinRT plumbing now lives in the owned, pure-Go
// github.com/go-mswin/winrt wrapper (over the reference saltosystems/winrt-go),
// so this file keeps only the Hello-specific policy.
package main

import (
	"errors"

	"github.com/go-mswin/winrt"
)

// errUserConsentDeclined is returned when Windows Hello is available and the
// user explicitly declines or cancels the verification prompt.
var errUserConsentDeclined = errors.New("windows hello: user consent declined")

// requestUserConsent surfaces the Windows Hello prompt with the given reason.
//
// Best-effort posture (unchanged from before, but now it actually works — the
// previous hand-rolled combase call used a wrong IUserConsentVerifierStatics
// IID and never resolved the factory): when Windows Hello is unavailable (not
// present, not enrolled, disabled by policy) or the WinRT runtime cannot be
// reached, we do NOT add a gate — the Credential Manager's own DPAPI protection
// still applies. Only when Hello IS available and the user explicitly declines
// or cancels the prompt do we refuse the credential release.
func requestUserConsent(reason string) error {
	avail, err := winrt.Available()
	if err != nil || !avail {
		// No Hello, or the runtime is unreachable: best-effort, no extra gate.
		return nil
	}
	verified, err := winrt.RequireUserConsent(reason)
	if err != nil {
		// Runtime failure while prompting: best-effort, do not block.
		return nil
	}
	if !verified {
		return errUserConsentDeclined
	}
	return nil
}
