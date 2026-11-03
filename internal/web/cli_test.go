package web

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"crypto/ed25519"
	"crypto/rand"

	"golang.org/x/crypto/ssh"

	"github.com/max-zit/passzit/internal/auth"
)

// router is an SSH device that takes RouterOS's /password command.
type router struct {
	mu       sync.Mutex
	user, pw string
	addr     string
}

func (d *router) password() string { d.mu.Lock(); defer d.mu.Unlock(); return d.pw }

func startRouter(t *testing.T, user, pw string) *router {
	d := &router{user: user, pw: pw}
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(priv)
	cfg := &ssh.ServerConfig{PasswordCallback: func(c ssh.ConnMetadata, p []byte) (*ssh.Permissions, error) {
		if c.User() == d.user && string(p) == d.password() {
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
			go func() {
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
						for req := range in {
							if req.Type != "exec" {
								_ = req.Reply(false, nil)
								continue
							}
							_ = req.Reply(true, nil)
							cmd := string(req.Payload[4:])
							get := func(k string) string {
								i := strings.Index(cmd, k+`="`)
								if i < 0 {
									return ""
								}
								v := cmd[i+len(k)+2:]
								return v[:strings.Index(v, `"`)]
							}
							d.mu.Lock()
							if strings.HasPrefix(cmd, "/password ") && get("old-password") == d.pw && get("new-password") == get("confirm-new-password") {
								d.pw = get("new-password")
							} else {
								_, _ = ch.Write([]byte("failure: old password is not valid"))
							}
							d.mu.Unlock()
							_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ C uint32 }{0}))
							return
						}
					}()
				}
			}()
		}
	}()
	return d
}

// TestCommandLineClient runs the real passzit binary against a test server:
// sign in, unlock for a session, list and read an item, lock.
func TestCommandLineClient(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the command-line client")
	}
	e := newEnv(t)
	admin := e.setupAdmin()
	e.srv.DevNo2FA = true // the command line signs in with the master password only
	vid := admin.personal()
	id := newUUID()
	secret := auth.NewTOTPSecret()
	admin.must("PUT", "/api/items/"+id, putItemReq{VaultID: vid, Data: admin.sealItem(vid, id, map[string]any{"type": "login", "name": "GitHub",
		"login": map[string]any{"username": "octo", "password": "Cli-Secret-42", "urls": []string{"https://github.com"}, "totp": secret}})}, nil)

	bin := filepath.Join(t.TempDir(), "passzit")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	if out, err := exec.Command("go", "build", "-o", bin, "../../cmd/passzit").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	home := t.TempDir()
	run := func(stdin string, env []string, args ...string) (string, error) {
		cmd := exec.Command(bin, args...) // #nosec G204 -- the binary just built
		cmd.Env = append(os.Environ(), "XDG_CONFIG_HOME="+home, "APPDATA="+home, "HOME="+home)
		cmd.Env = append(cmd.Env, env...)
		cmd.Stdin = strings.NewReader(stdin)
		out, err := cmd.Output()
		return strings.TrimSpace(string(out)), err
	}
	if _, err := run(admin.pw+"\n", nil, "login", "--server", e.ts.URL, "--email", admin.email); err != nil {
		t.Fatalf("login: %v", err)
	}
	if _, err := run("wrong\n", nil, "list"); err == nil {
		t.Fatal("a wrong master password opened the vault")
	}
	session, err := run(admin.pw+"\n", nil, "unlock", "--raw")
	if err != nil || len(session) < 40 {
		t.Fatalf("unlock: %q %v", session, err)
	}
	env := []string{"PASSZIT_SESSION=" + session}
	if out, err := run("", env, "list", "git"); err != nil || !strings.Contains(out, "GitHub") || !strings.Contains(out, "octo") {
		t.Fatalf("list: %q %v", out, err)
	}
	if out, err := run("", env, "get", "password", "GitHub"); err != nil || out != "Cli-Secret-42" {
		t.Fatalf("password: %q %v", out, err)
	}
	want, _ := auth.TOTPCode(secret, time.Now().Unix()/30)
	if out, err := run("", env, "get", "totp", "github"); err != nil || out != want {
		t.Fatalf("totp: %q want %q, %v", out, want, err)
	}
	if out, err := run("", nil, "generate", "--length", "30"); err != nil || len(out) != 30 {
		t.Fatalf("generate: %q %v", out, err)
	}
	// automatic password change: a RouterOS-like SSH device, then the item
	dev := startRouter(t, "admin", "Router-Old-1")
	host, port, _ := net.SplitHostPort(dev.addr)
	p, _ := strconv.Atoi(port)
	rid := newUUID()
	admin.must("PUT", "/api/items/"+rid, putItemReq{VaultID: vid, Data: admin.sealItem(vid, rid, map[string]any{"type": "login", "name": "Branch router",
		"login":    map[string]any{"username": "admin", "password": "Router-Old-1"},
		"connect":  map[string]any{"tool": "ssh", "host": host, "port": p},
		"rotation": map[string]any{"method": "mikrotik", "days": 30}})}, nil)
	if out, err := run("", env, "rotate", "--due", "--dry-run"); err != nil || !strings.Contains(out, "Branch router") || strings.Contains(out, "GitHub") {
		t.Fatalf("dry run: %q %v", out, err)
	}
	if out, err := run("", env, "rotate", "--due"); err != nil || !strings.Contains(out, "changed: Branch router") {
		t.Fatalf("rotate: %q %v", out, err)
	}
	newPw, err := run("", env, "get", "password", "Branch router")
	if err != nil || newPw == "Router-Old-1" || newPw != dev.password() {
		t.Fatalf("saved %q, device has %q (%v)", newPw, dev.password(), err)
	}
	if out, _ := run("", env, "get", "item", "Branch router"); !strings.Contains(out, "Router-Old-1") || !strings.Contains(out, `"last"`) {
		t.Fatalf("history and last change not kept: %s", out)
	}
	if out, _ := run("", env, "rotate", "--due"); !strings.Contains(out, "") {
		t.Fatal(out)
	}
	if _, err := run("", nil, "lock"); err != nil {
		t.Fatal(err)
	}
	if _, err := run("", env, "list"); err == nil {
		t.Fatal("the session still opens the vault after lock")
	}
	// it signed in as an extension-like device
	if _, page := admin.get("/account"); !strings.Contains(page, "PassZit CLI on") {
		t.Fatal("the command-line client is not listed under the sessions")
	}
}
