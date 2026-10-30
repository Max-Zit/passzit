//go:build windows

package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"github.com/max-zit/passzit/internal/connect"
)

func extraDirs() []string {
	pf, pf86 := os.Getenv("ProgramFiles"), os.Getenv("ProgramFiles(x86)")
	return []string{
		filepath.Join(os.Getenv("SystemRoot"), "System32"),
		filepath.Join(os.Getenv("SystemRoot"), "System32", "OpenSSH"),
		filepath.Join(pf, "PuTTY"), filepath.Join(pf86, "PuTTY"),
		filepath.Join(pf, "WinBox"), filepath.Join(pf86, "WinBox"),
		filepath.Join(os.Getenv("LOCALAPPDATA"), "Programs", "WinBox"),
		filepath.Join(pf, "WinSCP"), filepath.Join(pf86, "WinSCP"), filepath.Join(os.Getenv("LOCALAPPDATA"), "Programs", "WinSCP"),
		filepath.Join(pf, "TightVNC"), filepath.Join(pf86, "TightVNC"), filepath.Join(pf, "TigerVNC"), filepath.Join(pf86, "TigerVNC"),
		filepath.Join(pf, "RealVNC", "VNC Viewer"), filepath.Join(pf, "uvnc bvba", "UltraVNC"),
	}
}

// startDetached starts a program apart from the helper and from the
// browser that started it (browsers keep native hosts in a job that ends
// with them; breaking away keeps the connection open). A console program
// gets a window of its own.
func startDetached(c *exec.Cmd, console bool) (*exec.Cmd, error) {
	flags := uint32(windows.CREATE_NEW_PROCESS_GROUP)
	if console {
		flags |= windows.CREATE_NEW_CONSOLE
	} else {
		flags |= windows.DETACHED_PROCESS
	}
	c.SysProcAttr = &syscall.SysProcAttr{CreationFlags: flags | windows.CREATE_BREAKAWAY_FROM_JOB}
	if err := c.Start(); err == nil {
		return c, nil
	}
	// The job does not allow breaking away: start it inside.
	c2 := exec.Command(c.Path, c.Args[1:]...) // #nosec G204 -- the same checked command
	c2.Stdin = c.Stdin
	c2.SysProcAttr = &syscall.SysProcAttr{CreationFlags: flags}
	return c2, c2.Start()
}

var (
	advapi32       = windows.NewLazySystemDLL("advapi32.dll")
	procCredWrite  = advapi32.NewProc("CredWriteW")
	procCredDelete = advapi32.NewProc("CredDeleteW")
)

const (
	credTypeDomainPassword = 2
	credPersistSession     = 1
)

type credential struct {
	Flags              uint32
	Type               uint32
	TargetName         *uint16
	Comment            *uint16
	LastWritten        windows.Filetime
	CredentialBlobSize uint32
	CredentialBlob     *byte
	Persist            uint32
	AttributeCount     uint32
	Attributes         uintptr
	TargetAlias        *uint16
	UserName           *uint16
}

// writeCred stores a Windows credential for Remote Desktop (only for this
// logon session; removed again by the clean-up).
func writeCred(c *connect.WinCred) error {
	target, err := windows.UTF16PtrFromString(c.Target)
	if err != nil {
		return err
	}
	user, err := windows.UTF16PtrFromString(c.User)
	if err != nil {
		return err
	}
	pw, err := windows.UTF16FromString(c.Password)
	if err != nil {
		return err
	}
	pw = pw[:len(pw)-1] // without the final NUL
	blob := make([]byte, len(pw)*2)
	for i, v := range pw {
		blob[2*i], blob[2*i+1] = byte(v), byte(v>>8) // #nosec G115 -- the two bytes of a UTF-16 unit
	}
	defer func() {
		for i := range blob {
			blob[i] = 0
		}
	}()
	cred := credential{Type: credTypeDomainPassword, TargetName: target, UserName: user, Persist: credPersistSession,
		CredentialBlobSize: uint32(len(blob))} // #nosec G115 -- a password of at most 1024 characters
	if len(blob) > 0 {
		cred.CredentialBlob = &blob[0]
	}
	r, _, e := procCredWrite.Call(uintptr(unsafe.Pointer(&cred)), 0) // #nosec G103 -- the Windows API wants a pointer
	if r == 0 {
		return e
	}
	return nil
}

func deleteCred(targetName string) {
	t, err := windows.UTF16PtrFromString(targetName)
	if err != nil {
		return
	}
	_, _, _ = procCredDelete.Call(uintptr(unsafe.Pointer(t)), credTypeDomainPassword, 0) // #nosec G103 -- the Windows API wants a pointer
}

// The registry keys browsers read native-messaging hosts from (per user).
var chromeKeys = []string{
	`Software\Google\Chrome\NativeMessagingHosts\` + connect.HostName,
	`Software\Microsoft\Edge\NativeMessagingHosts\` + connect.HostName,
	`Software\Chromium\NativeMessagingHosts\` + connect.HostName,
	`Software\BraveSoftware\Brave-Browser\NativeMessagingHosts\` + connect.HostName,
}

var firefoxKey = `Software\Mozilla\NativeMessagingHosts\` + connect.HostName

func dataDir() string { return filepath.Join(os.Getenv("LOCALAPPDATA"), "PassZit") }

func registerHost(exe string, ids []string, firefox bool) error {
	if err := os.MkdirAll(dataDir(), 0o700); err != nil {
		return err
	}
	set := func(key, file string) error {
		k, _, err := registry.CreateKey(registry.CURRENT_USER, key, registry.SET_VALUE)
		if err != nil {
			return err
		}
		defer k.Close()
		return k.SetStringValue("", file)
	}
	if len(ids) > 0 {
		m, err := connect.ChromeManifest(exe, ids)
		if err != nil {
			return err
		}
		f := filepath.Join(dataDir(), "chrome-host.json")
		if err := os.WriteFile(f, m, 0o600); err != nil {
			return err
		}
		for _, k := range chromeKeys {
			if err := set(k, f); err != nil {
				return err
			}
		}
	}
	if firefox {
		m, err := connect.FirefoxManifest(exe)
		if err != nil {
			return err
		}
		f := filepath.Join(dataDir(), "firefox-host.json")
		if err := os.WriteFile(f, m, 0o600); err != nil {
			return err
		}
		if err := set(firefoxKey, f); err != nil {
			return err
		}
	}
	return nil
}

func unregisterHost() error {
	var errs []error
	for _, k := range append(append([]string(nil), chromeKeys...), firefoxKey) {
		if err := registry.DeleteKey(registry.CURRENT_USER, k); err != nil && !errors.Is(err, registry.ErrNotExist) && !errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
			errs = append(errs, err)
		}
	}
	_ = os.Remove(filepath.Join(dataDir(), "chrome-host.json"))
	_ = os.Remove(filepath.Join(dataDir(), "firefox-host.json"))
	return errors.Join(errs...)
}
