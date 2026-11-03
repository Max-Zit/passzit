package main

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf16"

	"golang.org/x/crypto/ssh"
)

// fakeDevice is an SSH server with one account whose password can change
// the way Linux (passwd), RouterOS (/password) or Windows (ChangePassword) do.
type fakeDevice struct {
	mu       sync.Mutex
	user, pw string
	addr     string
}

func startDevice(t *testing.T, user, pw string) *fakeDevice {
	t.Helper()
	d := &fakeDevice{user: user, pw: pw}
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(priv)
	cfg := &ssh.ServerConfig{PasswordCallback: func(c ssh.ConnMetadata, p []byte) (*ssh.Permissions, error) {
		d.mu.Lock()
		defer d.mu.Unlock()
		if c.User() == d.user && string(p) == d.pw {
			return nil, nil
		}
		return nil, fmt.Errorf("denied")
	}}
	cfg.AddHostKey(signer)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	d.addr = ln.Addr().String()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go d.serve(c, cfg)
		}
	}()
	return d
}

func (d *fakeDevice) password() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.pw
}

func (d *fakeDevice) set(old, nw string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if old != d.pw {
		return false
	}
	d.pw = nw
	return true
}

func (d *fakeDevice) serve(c net.Conn, cfg *ssh.ServerConfig) {
	_, chans, reqs, err := ssh.NewServerConn(c, cfg)
	if err != nil {
		return
	}
	go ssh.DiscardRequests(reqs)
	for nc := range chans {
		ch, in, err := nc.Accept()
		if err != nil {
			continue
		}
		go func() {
			defer ch.Close()
			status := func(code uint32) {
				_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ C uint32 }{code}))
			}
			for req := range in {
				switch req.Type {
				case "pty-req":
					_ = req.Reply(true, nil)
				case "exec":
					_ = req.Reply(true, nil)
					cmd := string(req.Payload[4:])
					status(d.run(ch, cmd))
					return
				default:
					_ = req.Reply(false, nil)
				}
			}
		}()
	}
}

func (d *fakeDevice) run(ch ssh.Channel, cmd string) uint32 {
	switch {
	case strings.HasSuffix(cmd, "passwd"):
		rd := bufio.NewReader(ch)
		ask := func(p string) string {
			_, _ = ch.Write([]byte(p))
			l, _ := rd.ReadString('\n')
			return strings.TrimSpace(l)
		}
		old := ask("Changing password for " + d.user + ".\r\nCurrent password: ")
		n1 := ask("\r\nNew password: ")
		n2 := ask("\r\nRetype new password: ")
		if n1 != n2 || !d.set(old, n1) {
			_, _ = ch.Write([]byte("passwd: Authentication token manipulation error\r\n"))
			return 10
		}
		_, _ = ch.Write([]byte("passwd: password updated successfully\r\n"))
		return 0
	case strings.HasPrefix(cmd, "/password "):
		get := func(k string) string {
			i := strings.Index(cmd, k+`="`)
			if i < 0 {
				return ""
			}
			v := cmd[i+len(k)+2:]
			return strings.ReplaceAll(v[:strings.Index(v, `"`)], `\$`, `$`)
		}
		if get("new-password") != get("confirm-new-password") || !d.set(get("old-password"), get("new-password")) {
			_, _ = ch.Write([]byte("failure: old password is not valid\r\n"))
		}
		return 0
	case strings.HasPrefix(cmd, "powershell "):
		raw, _ := base64.StdEncoding.DecodeString(cmd[strings.LastIndex(cmd, " ")+1:])
		u := make([]uint16, len(raw)/2)
		for i := range u {
			u[i] = binary.LittleEndian.Uint16(raw[2*i:])
		}
		ps := string(utf16.Decode(u))
		i := strings.Index(ps, "ChangePassword('")
		args := strings.Split(strings.TrimSuffix(ps[i+16:], "')"), "','")
		if len(args) != 2 || !d.set(args[0], args[1]) {
			_, _ = ch.Write([]byte("The specified network password is not correct."))
			return 1
		}
		return 0
	}
	return 127
}

func TestChangeOnDevice(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("APPDATA", t.TempDir())
	for _, method := range []string{"linux", "mikrotik", "windows"} {
		dev := startDevice(t, "admin", "Old-Pass-1")
		nw, err := newDevicePassword(24)
		if err != nil {
			t.Fatal(err)
		}
		if err := changeOnDevice(method, dev.addr, "admin", "Old-Pass-1", nw); err != nil {
			t.Fatalf("%s: %v", method, err)
		}
		if dev.password() != nw {
			t.Fatalf("%s: the device still has %q", method, dev.password())
		}
		if err := sshCheck(dev.addr, "admin", nw); err != nil {
			t.Fatalf("%s: the new password does not sign in: %v", method, err)
		}
		// a wrong current password changes nothing
		if err := changeOnDevice(method, dev.addr, "admin", "wrong", "x"); err == nil {
			t.Fatalf("%s: a wrong current password was accepted", method)
		}
	}
}

func TestDue(t *testing.T) {
	now := time.Now()
	it := rawItem{Data: map[string]any{"rotation": map[string]any{"method": "linux", "days": float64(30)}}}
	if !it.due(now) {
		t.Error("never changed: due")
	}
	it.Data["rotation"].(map[string]any)["last"] = now.Add(-10 * 24 * time.Hour).Format(time.RFC3339)
	if it.due(now) {
		t.Error("changed 10 days ago, every 30: not due")
	}
	it.Data["rotation"].(map[string]any)["last"] = now.Add(-31 * 24 * time.Hour).Format(time.RFC3339)
	if !it.due(now) {
		t.Error("changed 31 days ago: due")
	}
	if (rawItem{Data: map[string]any{}}).due(now) {
		t.Error("no setting: never due")
	}
}
