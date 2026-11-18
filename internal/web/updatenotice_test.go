package web

import (
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/max-zit/passzit/internal/update"
)

// hideNotice sends the × of the notice from page (as the Referer) and
// returns the status and where it leads.
func (c *client) hideNotice(referer string) (int, string) {
	c.e.t.Helper()
	req, _ := http.NewRequest(http.MethodPost, c.e.ts.URL+"/settings/version/hide-notice", strings.NewReader(""))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", c.e.ts.URL)
	if referer != "" {
		req.Header.Set("Referer", referer)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		c.e.t.Fatal(err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode, resp.Header.Get("Location")
}

// TestUpdateNotice: a newer release shows "PassZit X is available" at the
// top of every console page to administrators only (not on the Updates
// page); × hides it for five days in every browser of that administrator,
// a newer version shows it again at once; without the helper the text
// points to install.sh instead of an Install button.
func TestUpdateNotice(t *testing.T) {
	e := newEnv(t)
	e.srv.Version = "0.9.7"
	e.srv.HelperAvailable = func() bool { return true }
	admin := e.setupAdmin()
	user := e.inviteUser(admin, "bob@example.com", "Bob-Master-Password-22")
	const text = "PassZit 0.9.8 is available (installed: 0.9.7)."

	has := func(c *client, path string) bool {
		t.Helper()
		code, page := c.get(path)
		if code != http.StatusOK {
			t.Fatalf("%s: %d %.300s", path, code, page)
		}
		return strings.Contains(page, "PassZit 0.9.8 is available") || strings.Contains(page, "PassZit 0.9.9 is available")
	}
	// nothing newer known: no notice
	if has(admin, "/vault") {
		t.Fatal("notice without a newer release")
	}
	e.srv.upd.latest = &update.Manifest{Product: "passzit", Version: "0.9.8"}
	_, page := admin.get("/users")
	if !strings.Contains(page, text) || !strings.Contains(page, `href="/settings/version">Install<`) || !strings.Contains(page, "releases/tag/v0.9.8") || !strings.Contains(page, `action="/settings/version/hide-notice"`) {
		t.Fatal("the administrator does not see the notice with Install, notes and ×")
	}
	if !has(admin, "/vault") || !has(admin, "/settings/security") {
		t.Fatal("the notice is not on every page")
	}
	if has(admin, "/settings/version") {
		t.Fatal("the notice is shown on the Updates page itself")
	}
	// vault users never see it and cannot hide it
	if has(user, "/vault") || has(user, "/account") {
		t.Fatal("a vault user sees the notice")
	}
	if code, _ := user.hideNotice(e.ts.URL + "/vault"); code != http.StatusForbidden {
		t.Fatalf("a vault user hid the notice: %d", code)
	}
	// × goes back to the same page and hides it, also in another browser
	if code, loc := admin.hideNotice(e.ts.URL + "/users?q=bob"); code != http.StatusSeeOther || loc != "/users?q=bob" {
		t.Fatalf("hide: %d %q", code, loc)
	}
	if has(admin, "/users") {
		t.Fatal("the notice is still shown after ×")
	}
	other := e.client()
	other.email, other.pw, other.totp = admin.email, admin.pw, admin.totp
	e.tick()
	other.login()
	if has(other, "/vault") {
		t.Fatal("the hidden notice is back in another browser")
	}
	// never back to another site
	for _, ref := range []string{"https://evil.example/users", "", e.ts.URL + "//evil.example/x"} {
		if _, loc := admin.hideNotice(ref); loc != "/vault" {
			t.Fatalf("referer %q led to %q", ref, loc)
		}
	}
	// back after five days
	// (the session has run out by then: sign in again)
	e.clock = e.clock.Add(5*24*time.Hour + time.Minute)
	admin.login()
	if !has(admin, "/vault") {
		t.Fatal("the notice did not come back after five days")
	}
	admin.hideNotice(e.ts.URL + "/vault")
	if has(admin, "/vault") {
		t.Fatal("hidden again: still shown")
	}
	// a newer version shows it again at once
	e.srv.upd.latest = &update.Manifest{Product: "passzit", Version: "0.9.9"}
	if _, page := admin.get("/vault"); !strings.Contains(page, "PassZit 0.9.9 is available (installed: 0.9.7).") {
		t.Fatal("a newer version does not show the notice again")
	}
	// without the helper: no Install button, the way to install instead
	e.srv.HelperAvailable = func() bool { return false }
	_, page = admin.get("/vault")
	if strings.Contains(page, `href="/settings/version">Install<`) || !strings.Contains(page, "Install it with install.sh or the package of the release.") || !strings.Contains(page, ">Show how<") {
		t.Fatal("without the helper the notice still offers Install")
	}
	// the console's language
	if !strings.Contains(translate("sr", "PassZit %s is available (installed: %s).", "0.9.9", "0.9.7"), "Dostupan je PassZit 0.9.9") {
		t.Fatal("no Serbian text")
	}
}

func TestShowUpdateNotice(t *testing.T) {
	now := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
	later, earlier := now.Add(time.Hour), now.Add(-time.Hour)
	for _, c := range []struct {
		avail, hidden string
		until         *time.Time
		want          bool
	}{
		{"", "", nil, false},
		{"0.9.8", "", nil, true},
		{"0.9.8", "0.9.8", &later, false},
		{"0.9.8", "0.9.8", &earlier, true},
		{"0.9.9", "0.9.8", &later, true},
		{"0.9.8", "0.9.9", &later, false},
	} {
		if got := showUpdateNotice(c.avail, c.hidden, c.until, now); got != c.want {
			t.Errorf("%+v: %v", c, got)
		}
	}
}
