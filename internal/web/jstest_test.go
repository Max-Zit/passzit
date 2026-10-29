package web

import (
	"context"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/max-zit/passzit/internal/vaultcrypto"
)

func b32(s string) string { return base32.StdEncoding.EncodeToString([]byte(s)) }

// browserPath finds a Chromium-based browser for the JavaScript tests
// (PASSZIT_BROWSER overrides).
func browserPath() string {
	if p := os.Getenv("PASSZIT_BROWSER"); p != "" {
		return p
	}
	var list []string
	switch runtime.GOOS {
	case "windows":
		list = []string{`C:\Program Files\Google\Chrome\Application\chrome.exe`, `C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe`}
	case "darwin":
		list = []string{"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"}
	default:
		list = []string{"google-chrome", "google-chrome-stable", "chromium", "chromium-browser"}
	}
	for _, p := range list {
		if filepath.IsAbs(p) {
			if _, err := os.Stat(p); err == nil {
				return p
			}
		} else if q, err := exec.LookPath(p); err == nil {
			return q
		}
	}
	return ""
}

// TestJavaScriptCrypto runs the browser crypto (static/pz/crypto.js, the
// Argon2id WebAssembly module and the generator) in a headless browser and
// checks it against the Go reference: the same vectors, and values made on
// one side opened on the other.
func TestJavaScriptCrypto(t *testing.T) {
	br := browserPath()
	if br == "" {
		t.Skip("no Chromium-based browser found (set PASSZIT_BROWSER)")
	}
	if _, err := fs.Stat(staticFS, "static/pz/argon2.wasm"); err != nil {
		t.Skip("argon2.wasm is not built (go run ./tools/buildwasm)")
	}
	v := vaultcrypto.Vectors
	key, _ := hex.DecodeString(v.KeyHex)
	goSealed, _ := vaultcrypto.Seal(key, []byte("from go"), v.AAD)
	pub, priv, err := vaultcrypto.NewKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	goSealedTo, _ := vaultcrypto.SealTo(pub, []byte("sealed by go"), "x")
	rraw := vaultcrypto.Random(20)
	rtext := vaultcrypto.FormatRecoveryKey(vaultcrypto.Random(20))
	rparsed, _ := vaultcrypto.ParseRecoveryKey(rtext)
	c := map[string]any{"password": v.Password, "salt": v.SaltHex, "kdf": v.KDF, "key": v.KeyHex, "nonce": v.NonceHex, "aad": v.AAD, "plain": v.Plain,
		"goSealed": goSealed, "pub": vaultcrypto.B64.EncodeToString(pub), "priv": vaultcrypto.B64.EncodeToString(priv), "goSealedTo": goSealedTo,
		"recoveryRaw": hex.EncodeToString(rraw), "recoveryText": rtext,
		"totp": [][]string{{"SHA1", b32("12345678901234567890"), "94287082"}, {"SHA256", b32("12345678901234567890123456789012"), "46119246"},
			{"SHA512", b32("1234567890123456789012345678901234567890123456789012345678901234"), "90693936"}}}

	sub, _ := fs.Sub(staticFS, "static")
	mux := http.NewServeMux()
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.FS(sub))))
	mux.Handle("/ext/", http.StripPrefix("/ext/", http.FileServer(http.Dir(filepath.Join("..", "..", "extension", "src")))))
	mux.HandleFunc("/case.json", func(w http.ResponseWriter, r *http.Request) { _ = json.NewEncoder(w).Encode(c) })
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<!doctype html><meta charset="utf-8"><pre id="result">running</pre><script type="module" src="/jstest.js"></script>`))
	})
	result := make(chan []byte, 1)
	mux.HandleFunc("/result", func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		select {
		case result <- b:
		default:
		}
	})
	mux.HandleFunc("/jstest.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/javascript")
		http.ServeFile(w, r, filepath.Join("testdata", "jstest.js"))
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	// Chrome's helper processes may still write into the profile after it
	// exits: the profile is removed on a best-effort basis.
	profile, err := os.MkdirTemp("", "pzbrowser")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { time.Sleep(500 * time.Millisecond); _ = os.RemoveAll(profile) }()
	cmd := exec.CommandContext(ctx, br, "--headless=new", "--disable-gpu", "--no-first-run", "--no-default-browser-check", "--disable-extensions",
		"--user-data-dir="+profile, ts.URL+"/") // #nosec G204 -- the test's own browser and server
	if err := cmd.Start(); err != nil {
		t.Fatalf("browser: %v", err)
	}
	defer func() { cancel(); _ = cmd.Wait() }()
	var raw []byte
	select {
	case raw = <-result:
	case <-ctx.Done():
		t.Fatal("the browser did not report in time")
	}
	var got struct {
		Master, Auth, Wrap, PBKDF2, Sealed  string
		GoOpen, GoOpenSealed, WrongAAD      string
		JSSealedTo                          string `json:"jsSealedTo"`
		FileSealed                          string `json:"fileSealed"`
		FileRoundTrip                       bool   `json:"fileRoundTrip"`
		Recovery, RecoveryParsed            string
		Fingerprint                         string
		AccountRoundTrip                    bool
		Account                             map[string]string
		GenPassword, GenPhrase, Uniform, UU bool
		UUID                                bool `json:"uuid"`
		Sites, Matches, Imports, TOTP       []string
		Syntax                              []string
		SSH                                 struct{ PrivateKey, PublicKey, Fingerprint string }
		Error                               string
	}
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("result %q: %v", raw, err)
	}
	if got.Error != "" {
		t.Fatalf("browser error: %s", got.Error)
	}
	check := func(name, have, want string) {
		if have != want {
			t.Errorf("%s: browser %q, Go %q", name, have, want)
		}
	}
	check("master key", got.Master, v.MasterHex)
	check("auth key", got.Auth, v.AuthHex)
	check("wrap key", got.Wrap, v.Wrap)
	check("pbkdf2", got.PBKDF2, v.PBKDF2Master)
	check("sealed", got.Sealed, v.Sealed)
	check("open Go value", got.GoOpen, "from go")
	check("open Go sealed-to", got.GoOpenSealed, "sealed by go")
	check("wrong AAD", got.WrongAAD, "DecryptError")
	check("recovery format", got.Recovery, vaultcrypto.FormatRecoveryKey(rraw))
	check("recovery parse", got.RecoveryParsed, hex.EncodeToString(rparsed))
	check("fingerprint", got.Fingerprint, vaultcrypto.Fingerprint(pub))
	if p, err := vaultcrypto.OpenSealed(priv, got.JSSealedTo, "y"); err != nil || string(p) != "from javascript" {
		t.Errorf("Go cannot open the browser's sealed value: %q %v", p, err)
	}
	if p, err := vaultcrypto.Open(key, got.FileSealed, vaultcrypto.AADFile("f-1")); err != nil || string(p) != "file from javascript" || !got.FileRoundTrip {
		t.Errorf("browser file does not open in Go: %q %v", p, err)
	}
	// an account made in the browser opens in Go with the same password
	salt, _ := vaultcrypto.B64.DecodeString(got.Account["salt"])
	mk, _ := vaultcrypto.MasterKey("p\u00e4ssw\u00f6rd-Test-123", salt, vaultcrypto.KDF{Alg: "argon2id", M: 19456, T: 2, P: 1})
	ak, err := vaultcrypto.Open(vaultcrypto.Derive(mk, vaultcrypto.InfoWrap), got.Account["wrapped_account_key"], vaultcrypto.AADAccountKey())
	if err != nil || vaultcrypto.B64.EncodeToString(ak) != got.Account["account_key"] || vaultcrypto.B64.EncodeToString(vaultcrypto.Derive(mk, vaultcrypto.InfoAuth)) != got.Account["auth"] {
		t.Errorf("browser account does not open in Go: %v", err)
	}
	if len(got.Syntax) > 0 {
		t.Errorf("scripts that do not parse: %v", got.Syntax)
	}
	if len(got.TOTP) > 0 {
		t.Errorf("TOTP: %v", got.TOTP)
	}
	if k, err := ssh.ParseRawPrivateKey([]byte(got.SSH.PrivateKey)); err != nil {
		t.Errorf("browser SSH key does not parse: %v", err)
	} else if signer, err := ssh.NewSignerFromKey(k); err != nil {
		t.Errorf("SSH signer: %v", err)
	} else if pub := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey()))); !strings.HasPrefix(got.SSH.PublicKey, pub) || ssh.FingerprintSHA256(signer.PublicKey()) != got.SSH.Fingerprint {
		t.Errorf("SSH public key %q / %q, fingerprint %q / %q", got.SSH.PublicKey, pub, got.SSH.Fingerprint, ssh.FingerprintSHA256(signer.PublicKey()))
	}
	if len(got.Imports) > 0 {
		t.Errorf("import/export: %v", got.Imports)
	}
	if len(got.Sites)+len(got.Matches) > 0 {
		t.Errorf("domain matching: %v %v", got.Sites, got.Matches)
	}
	if !got.AccountRoundTrip || !got.GenPassword || !got.GenPhrase || !got.Uniform || !got.UUID {
		t.Errorf("browser checks: %+v", got)
	}
}
