//go:build !windows

package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"

	"github.com/max-zit/passzit/internal/connect"
)

func extraDirs() []string { return []string{"/usr/bin", "/usr/local/bin", "/snap/bin"} }

// startDetached starts a program in a session of its own.
func startDetached(c *exec.Cmd, _ bool) (*exec.Cmd, error) {
	c.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	return c, c.Start()
}

func writeCred(*connect.WinCred) error { return errors.New("only on Windows") }

func deleteCred(string) {}

// hostDirs are the per-user directories browsers read host manifests from.
func hostDirs() (chrome []string, firefox string) {
	home, _ := os.UserHomeDir()
	if runtime.GOOS == "darwin" {
		as := filepath.Join(home, "Library", "Application Support")
		return []string{filepath.Join(as, "Google", "Chrome", "NativeMessagingHosts"), filepath.Join(as, "Microsoft Edge", "NativeMessagingHosts"),
				filepath.Join(as, "Chromium", "NativeMessagingHosts"), filepath.Join(as, "BraveSoftware", "Brave-Browser", "NativeMessagingHosts"),
				filepath.Join(as, "Vivaldi", "NativeMessagingHosts")},
			filepath.Join(as, "Mozilla", "NativeMessagingHosts")
	}
	cfg := filepath.Join(home, ".config")
	return []string{filepath.Join(cfg, "google-chrome", "NativeMessagingHosts"), filepath.Join(cfg, "microsoft-edge", "NativeMessagingHosts"),
			filepath.Join(cfg, "chromium", "NativeMessagingHosts"), filepath.Join(cfg, "BraveSoftware", "Brave-Browser", "NativeMessagingHosts"),
			filepath.Join(cfg, "vivaldi", "NativeMessagingHosts")},
		filepath.Join(home, ".mozilla", "native-messaging-hosts")
}

func registerHost(exe string, ids []string, firefox bool) error {
	chrome, ff := hostDirs()
	name := connect.HostName + ".json"
	if len(ids) > 0 {
		m, err := connect.ChromeManifest(exe, ids)
		if err != nil {
			return err
		}
		for _, d := range chrome {
			if err := os.MkdirAll(d, 0o700); err != nil {
				return err
			}
			if err := os.WriteFile(filepath.Join(d, name), m, 0o600); err != nil {
				return err
			}
		}
	}
	if firefox {
		m, err := connect.FirefoxManifest(exe)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(ff, 0o700); err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(ff, name), m, 0o600)
	}
	return nil
}

func unregisterHost() error {
	chrome, ff := hostDirs()
	for _, d := range append(chrome, ff) {
		_ = os.Remove(filepath.Join(d, connect.HostName+".json"))
	}
	return nil
}
