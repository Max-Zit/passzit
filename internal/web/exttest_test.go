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
	"strconv"
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

// testCheckoutPage mixes fields with autocomplete names and fields found
// only by their names and labels, lists for the expiry and the country,
// and a field PassZit must leave alone.
const testCheckoutPage = `<!doctype html><meta charset="utf-8"><title>Checkout</title>
<form method="post" action="/testsite/done" onsubmit="return false">
<label>Full name <input name="fullname" autocomplete="name"></label>
<label>Street <input name="street"></label>
<label>ZIP <input name="zip"></label>
<label>City <input name="city"></label>
<label>Country <select name="country"><option value="">Choose</option><option value="DE">Germany</option><option value="RS">Serbia</option></select></label>
<label>E-mail <input name="mail" type="email"></label>
<label>Phone <input name="phone" type="tel"></label>
<label>Name on card <input name="cardholder"></label>
<label>Card number <input name="pan" autocomplete="cc-number"></label>
<label>Expiry month <select name="exp-month"><option value="">MM</option><option>01</option><option>02</option><option>03</option><option>04</option><option>05</option><option>06</option><option>07</option><option>08</option><option>09</option><option>10</option><option>11</option><option>12</option></select></label>
<label>Expiry year <select name="exp-year"><option value="">YYYY</option><option>2026</option><option>2027</option><option>2028</option><option>2029</option></select></label>
<label>CVC <input name="cvc" maxlength="4"></label>
<label>Delivery note <input name="note"></label>
<button type="submit">Pay</button></form>`

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
	demo   []string   // ids of the sample logins (screenshot mode)
}

func newExtFixture(t *testing.T) *extFixture {
	t.Helper()
	return newExtFixtureOn(t, false)
}

// newExtFixtureOn: with useTLS the test server runs over HTTPS (its own
// certificate), like a real PassZit server on a port of its own.
func newExtFixtureOn(t *testing.T, useTLS bool) *extFixture {
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
	mux.HandleFunc("/testsite/checkout", func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, testCheckoutPage) })
	mux.HandleFunc("/testsite/code", func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, testCodePage) })
	mux.HandleFunc("/testsite/open", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		to, _ := json.Marshal(r.FormValue("to"))
		_, _ = io.WriteString(w, "<!doctype html><script>location.href = "+string(to)+";</script>")
	})
	// a page under /launcher of the PassZit server: the extension's bridge script must answer there
	mux.HandleFunc("/launcher-probe", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `<!doctype html><title>probe</title><script>addEventListener("message", (e) => { if (e.data && e.data.type === "pz-ext-here") document.title = "here"; }); setTimeout(() => postMessage({ type: "pz-ext-ping" }, location.origin), 300);</script>`)
	})
	// a page of a MaxZit console (WatchZit) the user added in the extension
	// a website that makes and uses a passkey
	mux.HandleFunc("/passkey-probe", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `<!doctype html><title>passkey probe</title>`)
	})
	mux.HandleFunc("/console-probe", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `<!doctype html><title>console probe</title>`)
	})
	mux.HandleFunc("/vault-probe", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `<!doctype html><title>vault probe</title>`)
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
	if useTLS {
		f.ts = httptest.NewTLSServer(mux)
	} else {
		f.ts = httptest.NewServer(mux)
	}
	t.Cleanup(f.ts.Close)
	site := f.ts.URL + "/testsite/login"
	other := strings.Replace(f.ts.URL, "127.0.0.1", "localhost", 1) + "/testsite/login"
	vid := c.personal()
	id := newUUID()
	c.must("PUT", "/api/items/"+id, putItemReq{VaultID: vid, Data: c.sealItem(vid, id, map[string]any{"type": "login", "name": "Test site",
		"login": map[string]any{"username": "alice@example.com", "password": "S3cret-For-Test!", "urls": []string{site}, "totp": "JBSWY3DPEHPK3PXP"}})}, nil)
	id2 := newUUID()
	c.must("PUT", "/api/items/"+id2, putItemReq{VaultID: vid, Data: c.sealItem(vid, id2, map[string]any{"type": "note", "name": "Wi-Fi", "notes": "x"})}, nil)
	// a device login: "Open with" of a MaxZit console finds it by address and tool
	id3 := newUUID()
	c.must("PUT", "/api/items/"+id3, putItemReq{VaultID: vid, Data: c.sealItem(vid, id3, map[string]any{"type": "login", "name": "Probe server",
		"login": map[string]any{"username": "root", "password": "Device-Pass-1"}, "connect": map[string]any{"tool": "ssh", "host": "10.20.30.40", "port": 22}})}, nil)
	// a card and an identity for the checkout page (cards and addresses)
	id4 := newUUID()
	c.must("PUT", "/api/items/"+id4, putItemReq{VaultID: vid, Data: c.sealItem(vid, id4, map[string]any{"type": "card", "name": "Test card",
		"card": map[string]any{"holder": "Alice Example", "number": "4111 1111 1111 1111", "expMonth": "7", "expYear": "2028", "code": "123", "brand": "Visa"}})}, nil)
	id5 := newUUID()
	c.must("PUT", "/api/items/"+id5, putItemReq{VaultID: vid, Data: c.sealItem(vid, id5, map[string]any{"type": "identity", "name": "Home address",
		"identity": map[string]any{"first": "Alice", "last": "Example", "email": "alice@example.com", "phone": "+381 11 123456",
			"address1": "Main Street 1", "postal": "11000", "city": "Belgrade", "country": "Serbia"}})}, nil)
	f.query = url.Values{"server": {f.ts.URL}, "email": {"alice@example.com"}, "pw": {"Alice-Master-Password-9"}, "site": {site}, "other": {other}, "extra": {"2"}}
	// a device token for "Connect with the web vault", made by the web session
	var link extLoginResp
	c.must("POST", "/api/ext/link", map[string]string{"device": "Linked test"}, &link)
	f.query.Set("linktoken", link.Token)
	if os.Getenv("PZ_EXT_SHOTS") != "" {
		// sample logins for the screenshots of the store listings
		demo := []map[string]any{
			{"type": "login", "name": "GitHub", "login": map[string]any{"username": "alice", "password": "x", "urls": []string{"https://github.com/login"}, "totp": "JBSWY3DPEHPK3PXP"}},
			{"type": "login", "name": "Microsoft 365", "login": map[string]any{"username": "alice@contoso.com", "password": "x", "urls": []string{"https://login.microsoftonline.com"}}},
			{"type": "login", "name": "Office file server", "login": map[string]any{"username": "alice@contoso.com", "password": "x"}, "connect": map[string]any{"tool": "rdp", "host": "fs01.contoso.local", "port": 0}},
			{"type": "login", "name": "Web server", "login": map[string]any{"username": "root", "password": "x"}, "connect": map[string]any{"tool": "ssh", "host": "10.0.10.21", "port": 22}},
			{"type": "login", "name": "Branch router", "login": map[string]any{"username": "admin", "password": "x"}, "connect": map[string]any{"tool": "winbox", "host": "192.168.88.1", "port": 0}},
			{"type": "login", "name": "Company intranet", "login": map[string]any{"username": "alice@contoso.com", "password": "x", "urls": []string{site}, "totp": "JBSWY3DPEHPK3PXP"}},
			{"type": "login", "name": "Accounting portal", "login": map[string]any{"username": "alice@contoso.com", "password": "x", "urls": []string{"https://portal.example.com"}}},
		}
		for _, d := range demo {
			id := newUUID()
			c.must("PUT", "/api/items/"+id, putItemReq{VaultID: vid, Data: c.sealItem(vid, id, d)}, nil)
			f.demo = append(f.demo, id)
		}
		f.query.Set("extra", strconv.Itoa(2+len(demo)))
		f.query.Set("siteextra", "1") // Company intranet is a login of the test site
	}
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
	if n := f.steps(t); n < 15 {
		t.Errorf("only %d steps ran", n)
	}
	// the saved login reached the server, encrypted
	extra, _ := strconv.Atoi(f.query.Get("extra"))
	if s := f.c.sync(0); len(s.Items) != 5+extra {
		t.Errorf("server has %d items, want %d", len(s.Items), 5+extra)
	}
}

// steps waits for the harness, fails the test for every failed step and
// returns how many steps ran.
func (f *extFixture) steps(t *testing.T) int {
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
	return len(got.Steps)
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
		// only the sample logins stay; the extension syncs, and a tab of the
		// test site is the current tab of the popup's "This site"
		keep := map[string]bool{}
		for _, id := range f.demo {
			keep[id] = true
		}
		for _, it := range f.c.sync(0).Items {
			if !keep[it.ID] {
				f.c.must("POST", "/api/items/"+it.ID+"/trash", nil, nil)
			}
		}
		ext := "chrome-extension://" + loaded.ID
		if err := cdp.eval(ext+"/popup.html", `chrome.runtime.sendMessage({ type: "sync" })`); err != nil {
			t.Errorf("sync: %v", err)
		}
		if err := cdp.call("Target.createTarget", map[string]any{"url": f.query.Get("site")}, nil); err != nil {
			t.Errorf("site tab: %v", err)
		}
		time.Sleep(time.Second)
		cdp.background = true
		for _, view := range []string{"site", "all", "gen"} {
			if err := cdp.screenshot("chrome-extension://"+loaded.ID+"/popup.html#"+view, filepath.Join(shots, "popup-"+view+".png"), 360, 560, 2); err != nil {
				t.Errorf("screenshot %s: %v", view, err)
			}
		}
		storeImages(t, cdp, shots)
	}
}

// pipeCDP speaks the Chrome DevTools Protocol over --remote-debugging-pipe:
// JSON messages, each ended by a NUL byte.
type pipeCDP struct {
	w    io.Writer
	mu   sync.Mutex
	next int
	wait map[int]chan cdpReply
	// background makes screenshot tabs in a new window behind the current one
	background bool
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
// storeImages frames the popup screenshots into the images of the store
// listings (packaging/stores/frame.html, rendered by the same browser).
func storeImages(t *testing.T, cdp *pipeCDP, shots string) {
	frame, err := filepath.Abs(filepath.Join("..", "..", "packaging", "stores", "frame.html"))
	if err != nil {
		t.Fatal(err)
	}
	abs, _ := filepath.Abs(shots)
	page := func(q url.Values) string { return "file://" + filepath.ToSlash(frame) + "?" + q.Encode() }
	for i, s := range []struct{ img, title, text string }{
		{"popup-site.png", "Fills the right login", "User name, password and the 2FA code — only on the site they belong to."},
		{"popup-all.png", "All your vaults in one place", "Websites, RDP, SSH, WinBox and more, from your own PassZit server."},
		{"popup-gen.png", "Strong passwords in a click", "Random passwords and passphrases, saved encrypted right away."},
		{"", "Your server. Your keys.", "End-to-end encrypted in the browser. Open source, self-hosted, no tracking."},
	} {
		q := url.Values{"title": {s.title}, "text": {s.text}}
		if s.img != "" {
			q.Set("img", "file://"+filepath.ToSlash(filepath.Join(abs, s.img)))
		}
		if err := cdp.screenshot(page(q), filepath.Join(shots, fmt.Sprintf("store-%d.png", i+1)), 1280, 800, 1); err != nil {
			t.Errorf("store image %d: %v", i+1, err)
		}
	}
	if err := cdp.screenshot(page(url.Values{"tile": {"1"}}), filepath.Join(shots, "store-tile.png"), 440, 280, 1); err != nil {
		t.Errorf("store tile: %v", err)
	}
}

// eval runs a script in a new tab of pageURL and waits for its promise.
func (c *pipeCDP) eval(pageURL, expr string) error {
	var tgt struct {
		TargetID string `json:"targetId"`
	}
	if err := c.call("Target.createTarget", map[string]any{"url": pageURL}, &tgt); err != nil {
		return err
	}
	var att struct {
		SessionID string `json:"sessionId"`
	}
	if err := c.call("Target.attachToTarget", map[string]any{"targetId": tgt.TargetID, "flatten": true}, &att); err != nil {
		return err
	}
	time.Sleep(time.Second)
	if err := c.callIn(att.SessionID, "Runtime.evaluate", map[string]any{"expression": expr, "awaitPromise": true}, nil); err != nil {
		return err
	}
	return c.call("Target.closeTarget", map[string]any{"targetId": tgt.TargetID}, nil)
}

func (c *pipeCDP) screenshot(pageURL, file string, width, height int, scale float64) error {
	var tgt struct {
		TargetID string `json:"targetId"`
	}
	// background: a new window behind the current one, so the current tab
	// stays what the extension sees
	if err := c.call("Target.createTarget", map[string]any{"url": "about:blank", "newWindow": c.background, "background": c.background}, &tgt); err != nil {
		return err
	}
	var att struct {
		SessionID string `json:"sessionId"`
	}
	if err := c.call("Target.attachToTarget", map[string]any{"targetId": tgt.TargetID, "flatten": true}, &att); err != nil {
		return err
	}
	if err := c.callIn(att.SessionID, "Emulation.setDeviceMetricsOverride", map[string]any{"width": width, "height": height, "deviceScaleFactor": scale, "mobile": false}, nil); err != nil {
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
