package web

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

// firefoxPath finds Firefox for the extension test (PASSZIT_FIREFOX overrides).
func firefoxPath() string {
	if p := os.Getenv("PASSZIT_FIREFOX"); p != "" {
		return p
	}
	for _, p := range []string{"firefox", "firefox-esr", `C:\Program Files\Mozilla Firefox\firefox.exe`} {
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

// TestExtensionInFirefox runs the same harness as TestExtensionInBrowser
// with the Firefox build, installed as a temporary add-on over WebDriver
// BiDi (webExtension.install).
func TestExtensionInFirefox(t *testing.T) {
	ff := firefoxPath()
	if ff == "" {
		t.Skip("Firefox not found (set PASSZIT_FIREFOX)")
	}
	f := newExtFixture(t)
	extDir := f.build(t, "firefox")
	profile := browserProfile(t)
	// A fixed internal UUID makes the moz-extension:// address known.
	const uuid = "6f1d2a3b-4c5d-4e6f-8a9b-0c1d2e3f4a5b"
	prefs := `user_pref("extensions.webextensions.uuids", "{\"passzit@maxzit.com\":\"` + uuid + `\"}");
user_pref("extensions.originControls.grantByDefault", true);
user_pref("browser.shell.checkDefaultBrowser", false);
user_pref("datareporting.policy.dataSubmissionEnabled", false);
user_pref("remote.active-protocols", 1);
`
	if err := os.WriteFile(filepath.Join(profile, "user.js"), []byte(prefs), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, ff, "--headless", "--no-remote", "--profile", profile, "--remote-debugging-port", "0") // #nosec G204 -- the test's own browser
	stderr, err := cmd.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("firefox: %v", err)
	}
	defer func() { cancel(); _ = cmd.Wait() }()
	// Firefox prints where WebDriver BiDi listens.
	addr := make(chan string, 1)
	go func() {
		re := regexp.MustCompile(`WebDriver BiDi listening on (ws://[^\s]+)`)
		sc := bufio.NewScanner(stderr)
		for sc.Scan() {
			if m := re.FindStringSubmatch(sc.Text()); m != nil {
				select {
				case addr <- m[1]:
				default:
				}
			}
		}
	}()
	var ws string
	select {
	case ws = <-addr:
	case <-time.After(60 * time.Second):
		t.Fatal("Firefox did not start WebDriver BiDi")
	}
	bidi, err := dialBiDi(ws + "/session")
	if err != nil {
		t.Fatal(err)
	}
	defer bidi.close()
	if _, err := bidi.call("session.new", map[string]any{"capabilities": map[string]any{}}); err != nil {
		t.Fatal(err)
	}
	if _, err := bidi.call("webExtension.install", map[string]any{"extensionData": map[string]any{"type": "path", "path": extDir}}); err != nil {
		t.Fatalf("install the add-on: %v", err)
	}
	res, err := bidi.call("browsingContext.create", map[string]any{"type": "tab"})
	if err != nil {
		t.Fatal(err)
	}
	var bc struct {
		Context string `json:"context"`
	}
	_ = json.Unmarshal(res, &bc)
	harness := "moz-extension://" + uuid + "/test/harness.html?" + f.query.Encode()
	opener := f.ts.URL + "/testsite/open?to=" + url.QueryEscape(harness)
	if _, err := bidi.call("browsingContext.navigate", map[string]any{"context": bc.Context, "url": opener, "wait": "none"}); err != nil {
		t.Fatalf("open the harness: %v", err)
	}
	f.check(t)
}

// ---- a minimal WebSocket client (RFC 6455) for WebDriver BiDi

type bidiConn struct {
	conn net.Conn
	r    *bufio.Reader
	mu   sync.Mutex
	next int
	wait map[int]chan bidiReply
}

type bidiReply struct {
	ID     int             `json:"id"`
	Type   string          `json:"type"`
	Result json.RawMessage `json:"result"`
	Error  string          `json:"error"`
	Msg    string          `json:"message"`
}

func dialBiDi(wsURL string) (*bidiConn, error) {
	u := strings.TrimPrefix(wsURL, "ws://")
	host, path, _ := strings.Cut(u, "/")
	conn, err := net.DialTimeout("tcp", host, 10*time.Second)
	if err != nil {
		return nil, err
	}
	key := make([]byte, 16)
	_, _ = rand.Read(key)
	req := "GET /" + path + " HTTP/1.1\r\nHost: " + host + "\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: " +
		base64.StdEncoding.EncodeToString(key) + "\r\nSec-WebSocket-Version: 13\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		return nil, err
	}
	r := bufio.NewReader(conn)
	resp, err := http.ReadResponse(r, nil)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		return nil, fmt.Errorf("websocket handshake: %s", resp.Status)
	}
	c := &bidiConn{conn: conn, r: r, wait: map[int]chan bidiReply{}}
	go c.readLoop()
	return c, nil
}

func (c *bidiConn) close() { _ = c.conn.Close() }

func (c *bidiConn) readLoop() {
	for {
		msg, err := c.readFrame()
		if err != nil {
			return
		}
		var rep bidiReply
		if json.Unmarshal(msg, &rep) != nil || rep.ID == 0 {
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
}

// readFrame reads one (possibly fragmented) text message from the server.
func (c *bidiConn) readFrame() ([]byte, error) {
	var msg []byte
	for {
		h := make([]byte, 2)
		if _, err := io.ReadFull(c.r, h); err != nil {
			return nil, err
		}
		fin, op := h[0]&0x80 != 0, h[0]&0x0f
		n := uint64(h[1] & 0x7f)
		switch n {
		case 126:
			b := make([]byte, 2)
			if _, err := io.ReadFull(c.r, b); err != nil {
				return nil, err
			}
			n = uint64(binary.BigEndian.Uint16(b))
		case 127:
			b := make([]byte, 8)
			if _, err := io.ReadFull(c.r, b); err != nil {
				return nil, err
			}
			n = binary.BigEndian.Uint64(b)
		}
		if n > 64<<20 {
			return nil, errors.New("frame too large")
		}
		p := make([]byte, n)
		if _, err := io.ReadFull(c.r, p); err != nil {
			return nil, err
		}
		switch op {
		case 0x8:
			return nil, io.EOF
		case 0x9, 0xA: // ping, pong: Firefox does not need answers here
			continue
		}
		msg = append(msg, p...)
		if fin {
			return msg, nil
		}
	}
}

// writeText sends one masked text frame.
func (c *bidiConn) writeText(p []byte) error {
	var h []byte
	h = append(h, 0x81)
	switch n := len(p); {
	case n < 126:
		h = append(h, 0x80|byte(n))
	case n < 1<<16:
		h = append(h, 0x80|126, byte(n>>8), byte(n))
	default:
		b := make([]byte, 8)
		binary.BigEndian.PutUint64(b, uint64(n))
		h = append(append(h, 0x80|127), b...)
	}
	mask := make([]byte, 4)
	_, _ = rand.Read(mask)
	h = append(h, mask...)
	out := make([]byte, len(p))
	for i := range p {
		out[i] = p[i] ^ mask[i%4]
	}
	_, err := c.conn.Write(append(h, out...))
	return err
}

func (c *bidiConn) call(method string, params any) (json.RawMessage, error) {
	c.mu.Lock()
	c.next++
	id := c.next
	ch := make(chan bidiReply, 1)
	c.wait[id] = ch
	c.mu.Unlock()
	b, _ := json.Marshal(map[string]any{"id": id, "method": method, "params": params})
	if err := c.writeText(b); err != nil {
		return nil, err
	}
	select {
	case rep := <-ch:
		if rep.Type == "error" || rep.Error != "" {
			return nil, fmt.Errorf("%s: %s %s", method, rep.Error, rep.Msg)
		}
		return rep.Result, nil
	case <-time.After(30 * time.Second):
		return nil, fmt.Errorf("%s: no answer", method)
	}
}
