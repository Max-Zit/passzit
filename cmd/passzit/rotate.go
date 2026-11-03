package main

// passzit rotate changes the password of a device login on the device itself
// (over SSH) and then saves it in the vault — on this computer, so the server
// never sees a password. Items opt in under "Change the password on the
// device" in the web vault (method and interval); passzit rotate --due,
// started daily by cron or the Task Scheduler, changes all that are due.
//
// Order of work: a new password is made, the device is changed with the old
// one, the new one is checked with a fresh sign-in, and only then is the
// item saved (the old password goes into its history). If saving fails the
// new password is printed, so it is never lost.

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf16"

	"golang.org/x/crypto/ssh"

	"github.com/max-zit/passzit/internal/vaultcrypto"
)

// rotation is the item's "Change the password on the device" setting.
type rotation struct {
	Method string `json:"method"` // linux, mikrotik, windows
	Days   int    `json:"days"`
	Last   string `json:"last,omitempty"`
}

// rawItem keeps everything of an item, so a rewrite loses nothing.
type rawItem struct {
	ID, VaultID string
	Revision    int64
	Key         []byte
	Data        map[string]any
}

func (r rawItem) str(path ...string) string {
	var cur any = r.Data
	for _, p := range path {
		m, ok := cur.(map[string]any)
		if !ok {
			return ""
		}
		cur = m[p]
	}
	switch v := cur.(type) {
	case string:
		return v
	case float64:
		return strconv.Itoa(int(v))
	}
	return ""
}

func (r rawItem) rotation() *rotation {
	m, ok := r.Data["rotation"].(map[string]any)
	if !ok {
		return nil
	}
	b, _ := json.Marshal(m)
	var rt rotation
	if json.Unmarshal(b, &rt) != nil || rt.Method == "" {
		return nil
	}
	if rt.Days <= 0 {
		rt.Days = 90
	}
	return &rt
}

// due tells whether the password should change now.
func (r rawItem) due(now time.Time) bool {
	rt := r.rotation()
	if rt == nil {
		return false
	}
	last := rt.Last
	if last == "" {
		last = r.str("passwordChanged")
	}
	t, err := time.Parse(time.RFC3339, last)
	return err != nil || now.Sub(t) >= time.Duration(rt.Days)*24*time.Hour
}

func loadRaw(c *config, k *keys) ([]rawItem, error) {
	var d struct {
		Vaults []struct {
			ID         string `json:"id"`
			Kind       string `json:"kind"`
			WrappedKey string `json:"wrapped_key"`
		} `json:"vaults"`
		Items []struct {
			ID        string     `json:"id"`
			VaultID   string     `json:"vault_id"`
			Revision  int64      `json:"revision"`
			DeletedAt *time.Time `json:"deleted_at"`
			Data      string     `json:"data"`
		} `json:"items"`
	}
	if err := call(c.Server, c.Token, "GET", "/api/sync", nil, &d); err != nil {
		return nil, err
	}
	vk := map[string][]byte{}
	for _, v := range d.Vaults {
		var key []byte
		var err error
		if v.Kind == "personal" {
			key, err = vaultcrypto.Open(k.account, v.WrappedKey, vaultcrypto.AADVaultKey(v.ID))
		} else {
			key, err = vaultcrypto.OpenSealed(k.private, v.WrappedKey, vaultcrypto.AADVaultKey(v.ID))
		}
		if err == nil {
			vk[v.ID] = key
		}
	}
	var out []rawItem
	for _, it := range d.Items {
		key := vk[it.VaultID]
		if key == nil || it.DeletedAt != nil {
			continue
		}
		plain, err := vaultcrypto.Open(key, it.Data, vaultcrypto.AADItem(it.VaultID, it.ID))
		if err != nil {
			continue
		}
		var m map[string]any
		if json.Unmarshal(plain, &m) != nil {
			continue
		}
		out = append(out, rawItem{ID: it.ID, VaultID: it.VaultID, Revision: it.Revision, Key: key, Data: m})
	}
	return out, nil
}

// newDevicePassword avoids characters that shells and RouterOS quote.
func newDevicePassword(n int) (string, error) {
	const set = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789-_.%+=@"
	var b strings.Builder
	for i := 0; i < n; i++ {
		x, err := rand.Int(rand.Reader, big.NewInt(int64(len(set))))
		if err != nil {
			return "", err
		}
		b.WriteByte(set[x.Int64()])
	}
	return b.String(), nil
}

func cmdRotate(args []string) error {
	fs := flag.NewFlagSet("rotate", flag.ExitOnError)
	dueOnly := fs.Bool("due", false, "change every password that is due")
	dry := fs.Bool("dry-run", false, "only show what would change")
	length := fs.Int("length", 24, "length of the new passwords")
	_ = fs.Parse(args)
	if *length < 12 || *length > 64 {
		return errors.New("the length must be 12 to 64")
	}
	if !*dueOnly && fs.NArg() == 0 {
		return errors.New("usage: passzit rotate NAME-OR-ID | passzit rotate --due [--dry-run]")
	}
	c, err := signedIn()
	if err != nil {
		return err
	}
	k, err := unlockKeys(c)
	if err != nil {
		return err
	}
	all, err := loadRaw(c, k)
	if err != nil {
		return err
	}
	var todo []rawItem
	now := time.Now()
	if *dueOnly {
		for _, it := range all {
			if it.due(now) {
				todo = append(todo, it)
			}
		}
	} else {
		q := strings.Join(fs.Args(), " ")
		var cands []rawItem
		for _, it := range all {
			if it.ID == q || (len(q) >= 8 && strings.HasPrefix(it.ID, q)) || strings.EqualFold(it.str("name"), q) {
				cands = append(cands, it)
			}
		}
		if len(cands) != 1 {
			return fmt.Errorf("%d items match %q; use the id (passzit list)", len(cands), q)
		}
		if cands[0].rotation() == nil {
			return errors.New("this item has no \"Change the password on the device\" setting (web vault, Remote connection)")
		}
		todo = cands
	}
	failed := 0
	for _, it := range todo {
		name := it.str("name")
		if *dry {
			fmt.Printf("would change: %s (%s %s)\n", name, it.rotation().Method, it.str("connect", "host"))
			continue
		}
		if err := rotateOne(c, it, *length); err != nil {
			failed++
			fmt.Fprintf(os.Stderr, "%s: %v\n", name, err)
			continue
		}
		fmt.Printf("changed: %s\n", name)
	}
	if failed > 0 {
		return fmt.Errorf("%d of %d passwords were not changed", failed, len(todo))
	}
	if len(todo) == 0 {
		fmt.Fprintln(os.Stderr, "Nothing is due.")
	}
	return nil
}

func rotateOne(c *config, it rawItem, length int) error {
	rt := it.rotation()
	host, user, old := it.str("connect", "host"), it.str("login", "username"), it.str("login", "password")
	if host == "" || user == "" || old == "" {
		return errors.New("the item needs an address, a user name and the current password")
	}
	port := 22
	if it.str("connect", "tool") == "ssh" {
		if p, _ := strconv.Atoi(it.str("connect", "port")); p > 0 {
			port = p
		}
	}
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	nw, err := newDevicePassword(length)
	if err != nil {
		return err
	}
	if err := changeOnDevice(rt.Method, addr, user, old, nw); err != nil {
		return err
	}
	verifyErr := sshCheck(addr, user, nw)
	// save: the old password into the history, the new one in place
	now := time.Now().UTC().Format(time.RFC3339)
	d := it.Data
	login, _ := d["login"].(map[string]any)
	login["password"] = nw
	hist, _ := d["history"].([]any)
	hist = append(hist, map[string]any{"password": old, "changed": now})
	if len(hist) > 10 {
		hist = hist[len(hist)-10:]
	}
	d["history"] = hist
	d["passwordChanged"] = now
	rm, _ := d["rotation"].(map[string]any)
	rm["last"] = now
	plain, _ := json.Marshal(d)
	sealed, err := vaultcrypto.Seal(it.Key, plain, vaultcrypto.AADItem(it.VaultID, it.ID))
	if err == nil {
		err = call(c.Server, c.Token, "PUT", "/api/items/"+it.ID, map[string]any{"vault_id": it.VaultID, "data": sealed, "revision": it.Revision}, nil)
	}
	if err != nil {
		return fmt.Errorf("the device has the NEW password %q, but saving it failed (%v): write it down and save it in the web vault", nw, err)
	}
	if verifyErr != nil {
		return fmt.Errorf("changed and saved, but signing in with the new password failed (%v); the old one is in the item's history", verifyErr)
	}
	return nil
}

// ---- SSH

func knownHostsPath() (string, error) {
	p, err := configPath()
	if err != nil {
		return "", err
	}
	return filepath.Join(filepath.Dir(p), "known_hosts.json"), nil
}

var knownMu sync.Mutex

// hostKeyCheck trusts a device's key the first time (and remembers it);
// a different key later stops the change.
func hostKeyCheck(hostname string, _ net.Addr, key ssh.PublicKey) error {
	knownMu.Lock()
	defer knownMu.Unlock()
	p, err := knownHostsPath()
	if err != nil {
		return err
	}
	known := map[string]string{}
	if b, err := os.ReadFile(p); err == nil { // #nosec G304 -- the user's own config file
		_ = json.Unmarshal(b, &known)
	}
	k := base64.StdEncoding.EncodeToString(key.Marshal())
	if prev, ok := known[hostname]; ok {
		if prev != k {
			return fmt.Errorf("the SSH key of %s changed (%s) — if that is expected, remove it from %s", hostname, ssh.FingerprintSHA256(key), p)
		}
		return nil
	}
	known[hostname] = k
	b, _ := json.MarshalIndent(known, "", "  ")
	_ = os.MkdirAll(filepath.Dir(p), 0o700)
	return os.WriteFile(p, b, 0o600)
}

func sshConfig(user, password string) *ssh.ClientConfig {
	return &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{ssh.Password(password), ssh.KeyboardInteractive(func(_, _ string, qs []string, _ []bool) ([]string, error) {
			a := make([]string, len(qs))
			for i := range a {
				a[i] = password
			}
			return a, nil
		})},
		HostKeyCallback: hostKeyCheck,
		Timeout:         20 * time.Second,
	}
}

func sshCheck(addr, user, password string) error {
	cl, err := ssh.Dial("tcp", addr, sshConfig(user, password))
	if err != nil {
		return err
	}
	return cl.Close()
}

func changeOnDevice(method, addr, user, old, nw string) error {
	cl, err := ssh.Dial("tcp", addr, sshConfig(user, old))
	if err != nil {
		return fmt.Errorf("SSH sign-in with the current password: %w", err)
	}
	defer cl.Close()
	s, err := cl.NewSession()
	if err != nil {
		return err
	}
	defer s.Close()
	var out bytes.Buffer
	s.Stdout, s.Stderr = &out, &out
	switch method {
	case "mikrotik":
		q := func(v string) string {
			return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`, `$`, `\$`).Replace(v) + `"`
		}
		err = s.Run("/password old-password=" + q(old) + " new-password=" + q(nw) + " confirm-new-password=" + q(nw))
		if err == nil && strings.Contains(strings.ToLower(out.String()), "failure") {
			err = errors.New(strings.TrimSpace(out.String()))
		}
	case "windows":
		ps := "$ErrorActionPreference='Stop'; ([adsi]'WinNT://./" + strings.ReplaceAll(user, "'", "''") + ",user').ChangePassword('" +
			strings.ReplaceAll(old, "'", "''") + "','" + strings.ReplaceAll(nw, "'", "''") + "')"
		err = s.Run("powershell -NoProfile -NonInteractive -EncodedCommand " + utf16Base64(ps))
	case "linux":
		err = passwdOverPTY(s, &out, old, nw)
	default:
		return fmt.Errorf("unknown method %q", method)
	}
	if err != nil {
		msg := strings.TrimSpace(out.String())
		if len(msg) > 300 {
			msg = msg[len(msg)-300:]
		}
		return fmt.Errorf("the device refused the change: %v %s", err, msg)
	}
	return nil
}

func utf16Base64(s string) string {
	u := utf16.Encode([]rune(s))
	b := make([]byte, 2*len(u))
	for i, v := range u {
		binary.LittleEndian.PutUint16(b[2*i:], v)
	}
	return base64.StdEncoding.EncodeToString(b)
}

// passwdOverPTY answers the prompts of passwd: the current password first
// (when asked), then the new one twice.
func passwdOverPTY(s *ssh.Session, out *bytes.Buffer, old, nw string) error {
	if err := s.RequestPty("xterm", 24, 80, ssh.TerminalModes{ssh.ECHO: 0}); err != nil {
		return err
	}
	in, err := s.StdinPipe()
	if err != nil {
		return err
	}
	var mu sync.Mutex
	buf := &lockedBuffer{b: out, mu: &mu}
	s.Stdout, s.Stderr = buf, buf
	if err := s.Start("LC_ALL=C passwd"); err != nil {
		return err
	}
	done := make(chan error, 1)
	go func() { done <- s.Wait() }()
	answered, news := 0, 0
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-done:
			if news < 2 {
				return fmt.Errorf("passwd ended early: %v", err)
			}
			return err
		case <-time.After(150 * time.Millisecond):
		}
		text := strings.ToLower(buf.String())
		prompts := strings.Count(text, "password:")
		if prompts <= answered {
			continue
		}
		last := text[strings.LastIndex(text[:strings.LastIndex(text, "password:")+1], "\n")+1:]
		if strings.Contains(last, "current") || strings.Contains(last, "old") || strings.Contains(last, "(current)") {
			_, _ = in.Write([]byte(old + "\n"))
		} else {
			_, _ = in.Write([]byte(nw + "\n"))
			news++
		}
		answered = prompts
	}
	return errors.New("passwd did not finish in time")
}

type lockedBuffer struct {
	b  *bytes.Buffer
	mu *sync.Mutex
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}
