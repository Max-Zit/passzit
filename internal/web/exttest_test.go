package web

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/max-zit/passzit/internal/extpack"
)

const testLoginPage = `<!doctype html><meta charset="utf-8"><title>Test site</title>
<form method="post" action="/testsite/done">
<input name="trap" type="text" style="display:none">
<label>E-mail <input name="user" type="email"></label>
<label>Password <input name="pass" type="password"></label>
<button>Sign in</button></form>`

const testSignupPage = `<!doctype html><meta charset="utf-8"><title>Sign up</title>
<form method="post" action="/testsite/done" onsubmit="return false">
<label>E-mail <input name="user" type="email"></label>
<label>New password <input name="pass" type="password" autocomplete="new-password"></label>
<button type="submit">Create account</button></form>`

const testCodePage = `<!doctype html><meta charset="utf-8"><title>Two-step</title>
<form method="post" action="/testsite/done">
<label>Code from your app <input name="otp" inputmode="numeric" autocomplete="one-time-code"></label>
<button>Verify</button></form>`

// extFixture is a PassZit server with a test site, an account with two
// items, and an endpoint the extension's test harness reports to.
type extFixture struct {
	c      *client
	ts     *httptest.Server
	result chan []byte
	query  url.Values // harness parameters
}

func newExtFixture(t *testing.T) *extFixture {
	t.Helper()
	if _, err := os.Stat(filepath.Join("static", "pz", "argon2.wasm")); err != nil {
		t.Skip("argon2.wasm is not built (go run ./tools/buildwasm)")
	}
	e := newEnv(t)
	e.srv.DevNo2FA = true
	c := e.client()
	body := c.newAccount("alice@example.com", "Alice-Master-Password-9")
	body["token"] = "setup-token-123"
	c.must("POST", "/api/setup", body, nil)
	f := &extFixture{c: c, result: make(chan []byte, 1)}
	mux := http.NewServeMux()
	mux.HandleFunc("/testsite/login", func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, testLoginPage) })
	mux.HandleFunc("/testsite/signup", func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, testSignupPage) })
	mux.HandleFunc("/testsite/code", func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, testCodePage) })
	mux.HandleFunc("/testsite/open", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		to, _ := json.Marshal(r.FormValue("to"))
		_, _ = io.WriteString(w, "<!doctype html><script>location.href = "+string(to)+";</script>")
	})
	mux.HandleFunc("/testsite/done", func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "ok") })
	mux.HandleFunc("/harness-result", func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		select {
		case f.result <- b:
		default:
		}
	})
	mux.Handle("/", e.srv.Handler())
	f.ts = httptest.NewServer(mux)
	t.Cleanup(f.ts.Close)
	site := f.ts.URL + "/testsite/login"
	other := strings.Replace(f.ts.URL, "127.0.0.1", "localhost", 1) + "/testsite/login"
	vid := c.personal()
	id := newUUID()
	c.must("PUT", "/api/items/"+id, putItemReq{VaultID: vid, Data: c.sealItem(vid, id, map[string]any{"type": "login", "name": "Test site",
		"login": map[string]any{"username": "alice@example.com", "password": "S3cret-For-Test!", "urls": []string{site}, "totp": "JBSWY3DPEHPK3PXP"}})}, nil)
	id2 := newUUID()
	c.must("PUT", "/api/items/"+id2, putItemReq{VaultID: vid, Data: c.sealItem(vid, id2, map[string]any{"type": "note", "name": "Wi-Fi", "notes": "x"})}, nil)
	f.query = url.Values{"server": {f.ts.URL}, "email": {"alice@example.com"}, "pw": {"Alice-Master-Password-9"}, "site": {site}, "other": {other}}
	return f
}

// build makes the test build of the extension for a target.
func (f *extFixture) build(t *testing.T, target string) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "ext")
	if err := extpack.Build(extpack.Options{Root: filepath.Join("..", ".."), Target: target, Version: "0.0.1", Out: dir, Test: true}); err != nil {
		t.Fatal(err)
	}
	return dir
}

// check waits for the harness and fails the test for every failed step.
func (f *extFixture) check(t *testing.T) {
	t.Helper()
	var raw []byte
	select {
	case raw = <-f.result:
	case <-time.After(90 * time.Second):
		t.Fatal("the harness did not report")
	}
	var got struct {
		Steps []struct {
			Name, Info string
			OK         bool
		}
	}
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("result %s: %v", raw, err)
	}
	for _, s := range got.Steps {
		if !s.OK {
			t.Errorf("%s: %s", s.Name, s.Info)
		} else {
			t.Logf("ok: %s %s", s.Name, s.Info)
		}
	}
	if len(got.Steps) < 15 {
		t.Errorf("only %d steps ran", len(got.Steps))
	}
	// the saved login reached the server, encrypted
	if s := f.c.sync(0); len(s.Items) != 3 {
		t.Errorf("server has %d items, want 3", len(s.Items))
	}
}

func browserProfile(t *testing.T) string {
	t.Helper()
	p, err := os.MkdirTemp("", "pzext")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { time.Sleep(500 * time.Millisecond); _ = os.RemoveAll(p) })
	return p
}

// TestExtensionInBrowser loads the extension (test build) into headless
// Chrome and lets its harness sign in, sync, fill a login form, refuse to
// fill on another site, capture and save a new login, lock and unlock, all
// against a real PassZit server.
func TestExtensionInBrowser(t *testing.T) {
	br := browserPath()
	if br == "" {
		t.Skip("no Chromium-based browser found (set PASSZIT_BROWSER)")
	}
	// Branded Chrome no longer accepts --load-extension; the DevTools
	// command Extensions.loadUnpacked over --remote-debugging-pipe is the
	// supported way (the pipe is file descriptors 3 and 4, which Go cannot
	// hand to a child process on Windows).
	if runtime.GOOS == "windows" {
		t.Skip("the DevTools pipe needs Linux or macOS")
	}
	f := newExtFixture(t)
	extDir := f.build(t, "chromium")
	shots := os.Getenv("PZ_EXT_SHOTS") // a directory: save screenshots of the popup there
	if shots != "" {
		f.query.Set("stay", "1")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
	defer cancel()
	toChrome, ourEnd, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	fromChrome, chromeEnd, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(ctx, br, "--headless=new", "--no-first-run", "--no-default-browser-check", "--user-data-dir="+browserProfile(t), "--no-sandbox",
		"--remote-debugging-pipe", "--enable-unsafe-extension-debugging", "about:blank") // #nosec G204 -- the test's own browser
	cmd.ExtraFiles = []*os.File{toChrome, chromeEnd}
	if err := cmd.Start(); err != nil {
		t.Fatalf("browser: %v", err)
	}
	defer func() { cancel(); _ = cmd.Wait() }()
	_ = toChrome.Close()
	_ = chromeEnd.Close()
	cdp := newPipeCDP(ourEnd, fromChrome)
	var loaded struct {
		ID string `json:"id"`
	}
	if err := cdp.call("Extensions.loadUnpacked", map[string]any{"path": extDir}, &loaded); err != nil {
		t.Fatalf("load the extension: %v", err)
	}
	if err := cdp.call("Target.createTarget", map[string]any{"url": "chrome-extension://" + loaded.ID + "/test/harness.html?" + f.query.Encode()}, nil); err != nil {
		t.Fatalf("open the harness: %v", err)
	}
	f.check(t)
	if shots != "" {
		for _, view := range []string{"site", "all", "gen"} {
			if err := cdp.screenshot("chrome-extension://"+loaded.ID+"/popup.html#"+view, filepath.Join(shots, "popup-"+view+".png")); err != nil {
				t.Errorf("screenshot %s: %v", view, err)
			}
		}
	}
}

// pipeCDP speaks the Chrome DevTools Protocol over --remote-debugging-pipe:
// JSON messages, each ended by a NUL byte.
type pipeCDP struct {
	w    io.Writer
	mu   sync.Mutex
	next int
	wait map[int]chan cdpReply
}

type cdpReply struct {
	ID     int             `json:"id"`
	Result json.RawMessage `json:"result"`
	Error  *struct {
		Message string `json:"message"`
	} `json:"error"`
}

func newPipeCDP(w io.Writer, r io.Reader) *pipeCDP {
	c := &pipeCDP{w: w, wait: map[int]chan cdpReply{}}
	go func() {
		br := bufio.NewReader(r)
		for {
			msg, err := br.ReadBytes(0)
			if err != nil {
				return
			}
			var rep cdpReply
			if json.Unmarshal(msg[:len(msg)-1], &rep) != nil || rep.ID == 0 {
				continue // events
			}
			c.mu.Lock()
			ch := c.wait[rep.ID]
			delete(c.wait, rep.ID)
			c.mu.Unlock()
			if ch != nil {
				ch <- rep
			}
		}
	}()
	return c
}

func (c *pipeCDP) call(method string, params, out any) error {
	c.mu.Lock()
	c.next++
	id := c.next
	ch := make(chan cdpReply, 1)
	c.wait[id] = ch
	c.mu.Unlock()
	b, _ := json.Marshal(map[string]any{"id": id, "method": method, "params": params})
	if _, err := c.w.Write(append(b, 0)); err != nil {
		return err
	}
	select {
	case rep := <-ch:
		if rep.Error != nil {
			return fmt.Errorf("%s: %s", method, rep.Error.Message)
		}
		if out != nil {
			return json.Unmarshal(rep.Result, out)
		}
		return nil
	case <-time.After(30 * time.Second):
		return fmt.Errorf("%s: no answer", method)
	}
}

// callIn sends a command to an attached target (flat session mode).
func (c *pipeCDP) callIn(session, method string, params, out any) error {
	c.mu.Lock()
	c.next++
	id := c.next
	ch := make(chan cdpReply, 1)
	c.wait[id] = ch
	c.mu.Unlock()
	b, _ := json.Marshal(map[string]any{"id": id, "sessionId": session, "method": method, "params": params})
	if _, err := c.w.Write(append(b, 0)); err != nil {
		return err
	}
	select {
	case rep := <-ch:
		if rep.Error != nil {
			return fmt.Errorf("%s: %s", method, rep.Error.Message)
		}
		if out != nil {
			return json.Unmarshal(rep.Result, out)
		}
		return nil
	case <-time.After(30 * time.Second):
		return fmt.Errorf("%s: no answer", method)
	}
}

// screenshot opens a page at popup size and saves a PNG of it.
func (c *pipeCDP) screenshot(pageURL, file string) error {
	var tgt struct {
		TargetID string `json:"targetId"`
	}
	if err := c.call("Target.createTarget", map[string]any{"url": "about:blank"}, &tgt); err != nil {
		return err
	}
	var att struct {
		SessionID string `json:"sessionId"`
	}
	if err := c.call("Target.attachToTarget", map[string]any{"targetId": tgt.TargetID, "flatten": true}, &att); err != nil {
		return err
	}
	if err := c.callIn(att.SessionID, "Emulation.setDeviceMetricsOverride", map[string]any{"width": 360, "height": 560, "deviceScaleFactor": 2, "mobile": false}, nil); err != nil {
		return err
	}
	if err := c.callIn(att.SessionID, "Page.navigate", map[string]any{"url": pageURL}, nil); err != nil {
		return err
	}
	time.Sleep(2 * time.Second)
	var shot struct {
		Data string `json:"data"`
	}
	if err := c.callIn(att.SessionID, "Page.captureScreenshot", map[string]any{"format": "png"}, &shot); err != nil {
		return err
	}
	png, err := base64.StdEncoding.DecodeString(shot.Data)
	if err != nil {
		return err
	}
	return os.WriteFile(file, png, 0o600)
}
