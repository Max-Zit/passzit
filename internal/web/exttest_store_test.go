package web

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/max-zit/passzit/internal/extpack"
)

// TestExtensionStoreFlowFirefox does what a user does with the extension
// from the store, in real Firefox: the store build (no test harness, no
// host permissions) is installed, the popup gets the address of a server
// that runs over HTTPS on a port of its own, "Connect with the web vault"
// is clicked, the user signs in in the web vault and confirms there — and
// the extension must end up signed in and unlocked. Until 0.9.5 Firefox
// stopped at "The PassZit extension does not answer on this page".
func TestExtensionStoreFlowFirefox(t *testing.T) {
	ff := firefoxPath()
	if ff == "" {
		t.Skip("Firefox not found (set PASSZIT_FIREFOX)")
	}
	f := newExtFixtureOn(t, true)
	f.query.Set("mode", "store")
	dir := filepath.Join(t.TempDir(), "ext")
	if err := extpack.Build(extpack.Options{Root: filepath.Join("..", ".."), Target: "firefox", Version: "0.0.1", Out: dir}); err != nil {
		t.Fatal(err)
	}
	server := f.ts.URL // https://127.0.0.1:<port>
	prefs := `user_pref("extensions.originControls.grantByDefault", false);
user_pref("extensions.webextOptionalPermissionPrompts", false);
`
	runFirefox(t, ff, f, dir, prefs, map[string]any{"acceptInsecureCerts": true}, func(bidi *bidiConn, bc string) {
		eval := func(ctx, js string) (any, error) {
			raw, err := bidi.call("script.evaluate", map[string]any{"expression": js, "target": map[string]any{"context": ctx}, "awaitPromise": true})
			if err != nil {
				return nil, err
			}
			var r struct {
				Type   string `json:"type"`
				Result struct {
					Value any `json:"value"`
				} `json:"result"`
				ExceptionDetails any `json:"exceptionDetails"`
			}
			_ = json.Unmarshal(raw, &r)
			if r.Type == "exception" {
				return nil, fmt.Errorf("script: %v", r.ExceptionDetails)
			}
			return r.Result.Value, nil
		}
		// wait polls a condition in a page (true when it returns true)
		wait := func(ctx, js, what string, secs int) {
			t.Helper()
			var last any
			var lastErr error
			for i := 0; i < secs*4; i++ {
				v, err := eval(ctx, js)
				if v == true {
					return
				}
				last, lastErr = v, err
				time.Sleep(250 * time.Millisecond)
			}
			text, _ := eval(ctx, `document.body ? document.body.innerText.slice(0, 600) : ""`)
			where, _ := eval(ctx, `location.pathname + location.search.replace(/password=[^&]*/, "password=…") + " " + document.readyState + " [" + ((document.getElementById("pz-error") || {}).textContent || "") + "]"`)
			t.Fatalf("%s: not reached (%v %v); at %v; page: %v", what, last, lastErr, where, text)
		}
		click := func(ctx, selectorJS string) {
			t.Helper()
			v, err := eval(ctx, `(() => { const b = `+selectorJS+`; if (!b) return null; const r = b.getBoundingClientRect(); return [Math.round(r.x + r.width / 2), Math.round(r.y + r.height / 2)]; })()`)
			xy, ok := v.([]any)
			if err != nil || !ok || len(xy) != 2 {
				t.Fatalf("button not found: %v %v", v, err)
			}
			xv, yv := xy[0].(map[string]any)["value"], xy[1].(map[string]any)["value"]
			if _, err := bidi.call("input.performActions", map[string]any{"context": ctx, "actions": []any{map[string]any{
				"type": "pointer", "id": "mouse", "parameters": map[string]any{"pointerType": "mouse"},
				"actions": []any{
					map[string]any{"type": "pointerMove", "x": xv, "y": yv},
					map[string]any{"type": "pointerDown", "button": 0},
					map[string]any{"type": "pointerUp", "button": 0},
				}}}}); err != nil {
				t.Fatalf("click: %v", err)
			}
		}
		popup := "moz-extension://" + ffUUID + "/popup.html"
		if _, err := bidi.call("browsingContext.navigate", map[string]any{"context": bc, "url": popup, "wait": "complete"}); err != nil {
			t.Fatalf("open the popup: %v", err)
		}
		// 1. the popup: server address, "Connect with the web vault"
		wait(bc, `!!document.querySelector("input[type=url]")`, "sign-in form of the popup", 15)
		if _, err := eval(bc, `(() => { const i = document.querySelector("input[type=url]"); i.value = `+jsString(server)+`; return true; })()`); err != nil {
			t.Fatal(err)
		}
		click(bc, `[...document.querySelectorAll("button")].find((b) => b.textContent.includes("Connect with the web vault"))`)
		// 2. the web vault opens in a new tab: sign in there
		var vault string
		for i := 0; i < 60 && vault == ""; i++ {
			time.Sleep(250 * time.Millisecond)
			raw, err := bidi.call("browsingContext.getTree", map[string]any{})
			if err != nil {
				continue
			}
			var tree struct {
				Contexts []struct {
					Context, URL string
				} `json:"contexts"`
			}
			_ = json.Unmarshal(raw, &tree)
			for _, c := range tree.Contexts {
				if strings.HasPrefix(c.URL, server+"/") {
					vault = c.Context
				}
			}
		}
		if vault == "" {
			text, _ := eval(bc, `document.body ? document.body.innerText.slice(0, 400) : ""`)
			t.Fatalf("the web vault did not open (popup: %v)", text)
		}
		// readyState "complete": the page's module scripts ran, so the form
		// is PassZit's own (a submit before that is the browser's own GET,
		// which only loads the sign-in page again — on slow CI machines).
		wait(vault, `document.readyState === "complete" && !!document.querySelector("input[name=email]") && !!document.querySelector("input[name=password]")`, "sign-in page of the web vault", 30)
		if _, err := eval(vault, `(() => {
			const e = document.querySelector("input[name=email]"), p = document.querySelector("input[name=password]");
			e.value = "alice@example.com"; p.value = "Alice-Master-Password-9";
			e.form.requestSubmit(); return true; })()`); err != nil {
			t.Fatal(err)
		}
		time.Sleep(500 * time.Millisecond)
		if v, _ := eval(vault, `location.search`); strings.Contains(fmt.Sprint(v), "email=") {
			t.Fatalf("the sign-in form was sent by the browser, not by PassZit (%v)", v)
		}
		// 3. the vault asks to connect this browser's extension: confirm
		wait(vault, `!!document.querySelector("dialog.dlg[open]") && document.querySelector("dialog.dlg[open]").textContent.includes("Connect the PassZit extension")`, "the vault asks to connect the extension", 40)
		if _, err := eval(vault, `(() => { document.querySelector("dialog.dlg[open] button.primary").click(); return true; })()`); err != nil {
			t.Fatal(err)
		}
		wait(vault, `document.body.innerText.includes("The extension is connected and unlocked.")`, "the vault reports the extension connected", 20)
		// 4. the popup now shows the vault of this account
		// (in a new tab: the popup closed its own after "Connect")
		raw, err := bidi.call("browsingContext.create", map[string]any{"type": "tab"})
		if err != nil {
			t.Fatal(err)
		}
		var nc struct {
			Context string `json:"context"`
		}
		_ = json.Unmarshal(raw, &nc)
		if _, err := bidi.call("browsingContext.navigate", map[string]any{"context": nc.Context, "url": popup, "wait": "complete"}); err != nil {
			t.Fatalf("open the popup again: %v", err)
		}
		wait(nc.Context, `document.body.innerText.includes("Generator") && !document.body.innerText.includes("Sign in to PassZit")`, "the popup is signed in and unlocked", 15)
		f.result <- []byte(`{"steps":[{"name":"store flow","ok":true}]}`)
	})
	if n := f.steps(t); n != 1 {
		t.Errorf("%d steps", n)
	}
}

func jsString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}
