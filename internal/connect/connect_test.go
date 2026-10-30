package connect

import (
	"bytes"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
)

func fakeEnv(goos string, have ...string) Env {
	return Env{GOOS: goos, LookPath: func(names ...string) (string, error) {
		for _, n := range names {
			if slices.Contains(have, n) {
				return "/bin/" + n, nil
			}
		}
		return "", errors.New("not found")
	}}
}

func TestValidate(t *testing.T) {
	good := []Request{
		{V: 1, Tool: ToolRDP, Host: "srv01.example.local", User: `EXAMPLE\admin`, Password: "p w!"},
		{V: 1, Tool: ToolSSH, Host: "10.0.0.5", Port: 2222, User: "root"},
		{V: 1, Tool: ToolSSH, Host: "fe80::1", User: "pi"},
		{V: 1, Tool: ToolWinBox, Host: "192.168.88.1", User: "admin@local"},
	}
	for _, r := range good {
		if err := r.Validate(); err != nil {
			t.Errorf("%+v refused: %v", r, err)
		}
	}
	bad := []Request{
		{V: 2, Tool: ToolRDP, Host: "a"},
		{V: 1, Tool: "ftp", Host: "a"},
		{V: 1, Tool: ToolSSH, Host: "-oProxyCommand=calc"},
		{V: 1, Tool: ToolSSH, Host: "a b"},
		{V: 1, Tool: ToolSSH, Host: "a;b"},
		{V: 1, Tool: ToolSSH, Host: "a..b"},
		{V: 1, Tool: ToolSSH, Host: "ok", User: "-oProxyCommand"},
		{V: 1, Tool: ToolSSH, Host: "ok", User: "a b"},
		{V: 1, Tool: ToolSSH, Host: "ok", Port: 70000},
		{V: 1, Tool: ToolRDP, Host: "ok", Password: "a\nb"},
		{V: 1, Tool: ToolSSH, Host: "ok", Key: "not a key"},
	}
	for _, r := range bad {
		if r.Validate() == nil {
			t.Errorf("%+v accepted", r)
		}
	}
}

func TestPlan(t *testing.T) {
	win := fakeEnv("windows", "mstsc.exe", "putty.exe", "ssh.exe", "winbox64.exe")
	// RDP on Windows: a credential, no password on the command line
	a, err := Plan(Request{V: 1, Tool: ToolRDP, Host: "srv", Port: 3390, User: "admin", Password: "Secret-1"}, win)
	if err != nil || a.Cred == nil || a.Cred.Target != "TERMSRV/srv" || strings.Join(a.Args, " ") != "/v:srv:3390" {
		t.Fatalf("rdp %+v %v", a, err)
	}
	// SSH with a password: PuTTY reads a file
	a, _ = Plan(Request{V: 1, Tool: ToolSSH, Host: "h", User: "u", Password: "Secret-2"}, win)
	if a.Program != "/bin/putty.exe" || !slices.Contains(a.Args, "-pwfile") || strings.Contains(strings.Join(a.Args, " "), "Secret-2") || string(a.Secrets[0].Data) != "Secret-2" {
		t.Fatalf("putty %+v", a)
	}
	// without PuTTY: OpenSSH, the password goes to the clipboard
	a, _ = Plan(Request{V: 1, Tool: ToolSSH, Host: "h", User: "u", Password: "Secret-2"}, fakeEnv("windows", "ssh.exe"))
	if !a.Console || a.Response.Copy != "password" || slices.Contains(a.Args, "Secret-2") {
		t.Fatalf("openssh %+v", a)
	}
	// SSH with a key: a temporary key file; "--" ends the options
	key := "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----"
	a, _ = Plan(Request{V: 1, Tool: ToolSSH, Host: "h", Port: 2200, User: "u", Key: key, Passphrase: "pp"}, win)
	if a.Args[1] != "{key}" || a.Args[len(a.Args)-2] != "--" || a.Args[len(a.Args)-1] != "u@h" || a.Response.Copy != "passphrase" || !strings.HasSuffix(string(a.Secrets[0].Data), "-----\n") {
		t.Fatalf("ssh key %+v", a)
	}
	// WinBox only on Windows
	a, _ = Plan(Request{V: 1, Tool: ToolWinBox, Host: "192.168.88.1", User: "admin", Password: "x"}, win)
	if strings.Join(a.Args, " ") != "192.168.88.1 admin x" {
		t.Fatalf("winbox %+v", a)
	}
	if _, err := Plan(Request{V: 1, Tool: ToolWinBox, Host: "h"}, fakeEnv("linux")); err == nil {
		t.Fatal("winbox on linux")
	}
	// Linux: xfreerdp reads the password from stdin, ssh in a terminal
	lin := fakeEnv("linux", "xfreerdp", "ssh", "x-terminal-emulator")
	a, _ = Plan(Request{V: 1, Tool: ToolRDP, Host: "srv", User: "admin", Password: "Secret-3"}, lin)
	if a.Stdin != "Secret-3\n" || slices.Contains(a.Args, "Secret-3") || !slices.Contains(a.Args, "/from-stdin") {
		t.Fatalf("xfreerdp %+v", a)
	}
	a, _ = Plan(Request{V: 1, Tool: ToolSSH, Host: "h", User: "u"}, lin)
	if a.Program != "/bin/x-terminal-emulator" || a.Args[0] != "-e" || a.Args[1] != "/bin/ssh" {
		t.Fatalf("terminal %+v", a)
	}
	// IPv6 with a port
	a, _ = Plan(Request{V: 1, Tool: ToolRDP, Host: "fe80::1", Port: 3390}, win)
	if a.Args[0] != "/v:[fe80::1]:3390" {
		t.Fatalf("ipv6 %v", a.Args)
	}
	if _, err := Plan(Request{V: 1, Tool: ToolRDP, Host: "srv"}, fakeEnv("windows")); err == nil {
		t.Fatal("missing mstsc not reported")
	}
	// WinSCP, VNC and Telnet ask for the password themselves: clipboard
	more := fakeEnv("windows", "winscp.exe", "tvnviewer.exe", "putty.exe")
	a, _ = Plan(Request{V: 1, Tool: ToolWinSCP, Host: "files", User: `DOM\u`, Password: "Secret-4"}, more)
	if strings.Join(a.Args, " ") != "sftp://DOM%5Cu@files:22/" || a.Response.Copy != "password" {
		t.Fatalf("winscp %+v", a)
	}
	a, _ = Plan(Request{V: 1, Tool: ToolVNC, Host: "pc", Password: "Secret-5"}, more)
	if strings.Join(a.Args, " ") != "pc::5900" || a.Response.Copy != "password" {
		t.Fatalf("vnc %+v", a)
	}
	a, _ = Plan(Request{V: 1, Tool: ToolTelnet, Host: "sw", Port: 2323}, more)
	if strings.Join(a.Args, " ") != "-telnet -P 2323 sw" || a.Response.Copy != "" {
		t.Fatalf("telnet %+v", a)
	}
	for _, r := range []Request{{V: 1, Tool: ToolWinSCP, Host: "h", Password: "Secret-6"}, {V: 1, Tool: ToolVNC, Host: "h", Password: "Secret-6"}} {
		if a, err := Plan(r, more); err != nil || slices.Contains(a.Args, "Secret-6") {
			t.Fatalf("%s puts the password on the command line: %+v %v", r.Tool, a, err)
		}
	}
	if _, err := Plan(Request{V: 1, Tool: ToolWinSCP, Host: "h"}, fakeEnv("linux")); err == nil {
		t.Fatal("winscp on linux")
	}
}

func TestMessages(t *testing.T) {
	var b bytes.Buffer
	if err := WriteMessage(&b, Response{OK: true, Copy: "password"}); err != nil {
		t.Fatal(err)
	}
	raw, err := ReadMessage(&b)
	if err != nil {
		t.Fatal(err)
	}
	var r Response
	if json.Unmarshal(raw, &r) != nil || !r.OK || r.Copy != "password" {
		t.Fatalf("round trip %s", raw)
	}
	if _, err := ReadMessage(bytes.NewReader([]byte{0xff, 0xff, 0xff, 0x7f})); err == nil {
		t.Fatal("huge message accepted")
	}
}

func TestManifests(t *testing.T) {
	id := strings.Repeat("a", 32)
	m, err := ChromeManifest(`C:\PassZit\passzit-helper.exe`, []string{id})
	if err != nil || !strings.Contains(string(m), "chrome-extension://"+id+"/") || !strings.Contains(string(m), HostName) {
		t.Fatalf("chrome manifest %s %v", m, err)
	}
	if _, err := ChromeManifest("x", []string{"not-an-id"}); err == nil {
		t.Fatal("bad id accepted")
	}
	if _, err := ChromeManifest("x", nil); err == nil {
		t.Fatal("no id accepted")
	}
	if m, _ := FirefoxManifest("/usr/bin/passzit-helper"); !strings.Contains(string(m), FirefoxID) {
		t.Fatalf("firefox manifest %s", m)
	}
}
