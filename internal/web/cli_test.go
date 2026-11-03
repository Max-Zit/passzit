package web

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/max-zit/passzit/internal/auth"
)

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
