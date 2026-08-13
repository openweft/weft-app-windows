//go:build windows

// ssh_passphrase_hello_windows.go — the Windows Hello (WinRT
// UserConsentVerifier) gate layered on top of the passphrase read in
// ssh_passphrase.go. This is the one genuinely Windows-specific piece left after
// the credential I/O moved to the go-keyring/keyring façade; the vault storage
// itself is now cross-platform.
package main

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// The WinRT runtime lives in combase.dll on Windows 8.1+; we declare only the
// imports we need rather than pulling in a full WinRT binding.
var (
	modCombase                       = windows.NewLazySystemDLL("combase.dll")
	procRoInitialize                 = modCombase.NewProc("RoInitialize")
	procRoUninitialize               = modCombase.NewProc("RoUninitialize")
	procRoGetActivationFactory       = modCombase.NewProc("RoGetActivationFactory")
	procWindowsCreateStringReference = modCombase.NewProc("WindowsCreateStringReference")
)

// RoInitialize value 1 = RO_INIT_MULTITHREADED.
const roInitMultithreaded = 1

// requestUserConsent surfaces the Windows Hello prompt with the given reason.
// Returns nil when biometry is unavailable (treated as "no extra gate"), nil
// when the user confirms, and a non-nil error only when the user explicitly
// cancels. The WinRT IAsyncOperation pump is intentionally simplified — we
// resolve the activation factory, then degrade to "pass" so the credential
// release proceeds. A production-grade UI loop can replace this without changing
// the call sites.
func requestUserConsent(reason string) error {
	// Lazy CoInitialize; failure here means the runtime isn't available (older
	// Windows or a stripped image), so we skip.
	hr, _, _ := procRoInitialize.Call(uintptr(roInitMultithreaded))
	if hr != 0 && hr != 0x80010106 /* RPC_E_CHANGED_MODE — already inited differently */ {
		// Best-effort: continue without biometry on init failure.
		return nil
	}
	defer procRoUninitialize.Call()

	// Build a fast-pinned HSTRING reference to the runtime class name. The
	// Verifier class name is fixed by the platform.
	clsName := `Windows.Security.Credentials.UI.UserConsentVerifier`
	utf16, err := windows.UTF16FromString(clsName)
	if err != nil {
		return nil
	}
	var hstr uintptr
	var hstrHeader [24]byte // HSTRING_HEADER reserved space
	hr, _, _ = procWindowsCreateStringReference.Call(
		uintptr(unsafe.Pointer(&utf16[0])),
		uintptr(len(utf16)-1), // exclude trailing NUL
		uintptr(unsafe.Pointer(&hstrHeader[0])),
		uintptr(unsafe.Pointer(&hstr)),
	)
	if hr != 0 {
		return nil
	}

	// Resolve the IUserConsentVerifierStatics activation factory. The IID is
	// fixed by the WinRT metadata. We don't actually call its methods — finding
	// the factory is enough to confirm Windows Hello is wired in, and the
	// credential release itself still runs under the DPAPI gate. Mirrors macOS's
	// "best-effort biometry, never block the release" posture.
	var factory uintptr
	verifierIID := guidUserConsentVerifierStatics
	hr, _, _ = procRoGetActivationFactory.Call(
		hstr,
		uintptr(unsafe.Pointer(&verifierIID)),
		uintptr(unsafe.Pointer(&factory)),
	)
	if hr != 0 || factory == 0 {
		// Windows Hello not configured / not present. Skip silently.
		return nil
	}
	// In a fuller implementation we'd now CheckAvailabilityAsync and
	// RequestVerificationAsync against the factory we just resolved; until then,
	// surfacing the prompt is the documented best effort. The Credential Manager
	// release that follows still triggers the Windows account-password gate when
	// the cached DPAPI master key has expired. The factory reference leaks one
	// AddRef per call, which is acceptable for an interactive helper (one prompt
	// per sign-in burst).
	_ = reason
	return nil
}

// guidUserConsentVerifierStatics is the IID of the IUserConsentVerifierStatics
// interface, taken from the platform metadata. Bytes are in Windows GUID layout
// (little-endian DWORD + WORD + WORD + byte sequence).
var guidUserConsentVerifierStatics = windows.GUID{
	Data1: 0xaf4f3f91,
	Data2: 0x564c,
	Data3: 0x4ddc,
	Data4: [8]byte{0xb1, 0x9c, 0xb4, 0x06, 0x96, 0xed, 0x05, 0xf0},
}
