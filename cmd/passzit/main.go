// passzit is the command-line client of a PassZit server: sign in once,
// unlock for a shell session, then read logins in scripts — everything is
// decrypted on this computer, like in the browser.
//
//	passzit login --server https://vault.example.com --email me@example.com
//	export PASSZIT_SESSION="$(passzit unlock --raw)"
//	passzit list github
//	passzit get password "GitHub"
//	passzit get totp "GitHub"
//	passzit generate --length 24
//	passzit lock
//
// The device token (like a browser extension's) and, while unlocked, the
// account key sealed with the session key are stored in the user's config
// directory (passzit/cli.json, readable only by the user). Without
// PASSZIT_SESSION the commands ask for the master password.
package main

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" // #nosec G505 -- TOTP (RFC 6238) uses HMAC-SHA1 by default
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"hash"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/term"

	"github.com/max-zit/passzit/internal/vaultcrypto"
)

var version = "dev"

const usage = `PassZit command line client %s

  passzit login [--server URL] [--email ADDRESS]   sign this computer in (once)
  passzit unlock [--raw]                           unlock for a shell session (prints PASSZIT_SESSION)
  passzit lock                                     forget the session key
  passzit list [TEXT]                              list items, optionally only matching TEXT
  passzit get password|username|totp|notes|url|item NAME-OR-ID
  passzit generate [--length N] [--words N]        a new password or passphrase
  passzit status                                   server, account, locked or not
  passzit logout                                   sign this computer out

Without PASSZIT_SESSION the commands ask for the master password.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, usage, version)
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	var err error
	switch cmd {
	case "login":
		err = cmdLogin(args)
	case "unlock":
		err = cmdUnlock(args)
	case "lock":
		err = cmdLock()
	case "list":
		err = cmdList(args)
	case "get":
		err = cmdGet(args)
	case "generate":
		err = cmdGenerate(args)
	case "status":
		err = cmdStatus()
	case "logout":
		err = cmdLogout()
	case "version", "--version":
		fmt.Println(version)
	case "help", "-h", "--help":
		fmt.Printf(usage, version)
	default:
		err = fmt.Errorf("unknown command %q (passzit help)", cmd)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "passzit:", err)
		os.Exit(1)
	}
}

// ---- configuration

type config struct {
	Server string `json:"server"`
	Email  string `json:"email"`
	Token  string `json:"token"`
	Device string `json:"device"`
	// SessionKey is the account key sealed with PASSZIT_SESSION.
	SessionKey string `json:"session_key,omitempty"` // #nosec G117 -- sealed; useless without PASSZIT_SESSION
}

func configPath() (string, error) {
	d, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, "passzit", "cli.json"), nil
}

func loadConfig() (*config, error) {
	p, err := configPath()
	if err != nil {
		return nil, err
	}
	c := &config{}
	b, err := os.ReadFile(p) // #nosec G304 -- the user's own config file
	if errors.Is(err, os.ErrNotExist) {
		return c, nil
	}
	if err != nil {
		return nil, err
	}
	return c, json.Unmarshal(b, c)
}

func (c *config) save() error {
	p, err := configPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(c, "", "  ") // #nosec G117 -- the session key is sealed, the file readable only by the user
	return os.WriteFile(p, b, 0o600)
}

// ---- server API

type apiError struct {
	Status  int
	Message string
}

func (e *apiError) Error() string { return e.Message }

func call(server, token, method, path string, body, out any) error {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, strings.TrimRight(server, "/")+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "passzit-cli/"+version)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := (&http.Client{Timeout: 60 * time.Second}).Do(req) // #nosec G704 -- the server the user signed in to
	if err != nil {
		return fmt.Errorf("the server cannot be reached: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if resp.StatusCode >= 300 {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(raw, &e)
		if e.Error == "" {
			e.Error = resp.Status
		}
		if resp.StatusCode == http.StatusUnauthorized && token != "" {
			e.Error += " (sign in again: passzit login)"
		}
		return &apiError{resp.StatusCode, e.Error}
	}
	if out != nil {
		return json.Unmarshal(raw, out)
	}
	return nil
}

// ---- prompts

var stdin = bufio.NewReader(os.Stdin)

func prompt(label string) (string, error) {
	fmt.Fprint(os.Stderr, label)
	s, err := stdin.ReadString('\n')
	if err != nil && s == "" {
		return "", err
	}
	return strings.TrimSpace(s), nil
}

func promptSecret(label string) (string, error) {
	fd := int(os.Stdin.Fd()) // #nosec G115 -- a file descriptor
	if !term.IsTerminal(fd) {
		return prompt(label)
	}
	fmt.Fprint(os.Stderr, label)
	b, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	return string(b), err
}

// ---- keys

type account struct {
	Email             string          `json:"email"`
	PublicKey         string          `json:"public_key"`
	WrappedAccountKey string          `json:"wrapped_account_key"`
	WrappedPrivateKey string          `json:"wrapped_private_key"`
	Salt              string          `json:"salt"`
	KDF               vaultcrypto.KDF `json:"kdf"`
}

type keys struct {
	account, private []byte
}

var b64 = base64.RawURLEncoding

func signedIn() (*config, error) {
	c, err := loadConfig()
	if err != nil {
		return nil, err
	}
	if c.Token == "" {
		return nil, errors.New("not signed in (passzit login)")
	}
	return c, nil
}

// unlockKeys opens the account key: from the session, or with the master
// password.
func unlockKeys(c *config) (*keys, error) {
	var acct account
	if err := call(c.Server, c.Token, "GET", "/api/account", nil, &acct); err != nil {
		return nil, err
	}
	var ak []byte
	if s := os.Getenv("PASSZIT_SESSION"); s != "" && c.SessionKey != "" {
		sk, err := b64.DecodeString(s)
		if err == nil {
			ak, err = vaultcrypto.Open(sk, c.SessionKey, "passzit/cli-session/v1")
		}
		if err != nil {
			return nil, errors.New("PASSZIT_SESSION does not fit (unlock again)")
		}
	} else {
		pw, err := promptSecret("Master password: ")
		if err != nil {
			return nil, err
		}
		if ak, err = accountKeyFromPassword(&acct, pw); err != nil {
			return nil, err
		}
	}
	priv, err := vaultcrypto.Open(ak, acct.WrappedPrivateKey, vaultcrypto.AADPrivateKey())
	if err != nil {
		return nil, errors.New("the keys do not open this account")
	}
	return &keys{ak, priv}, nil
}

func accountKeyFromPassword(acct *account, password string) ([]byte, error) {
	salt, err := b64.DecodeString(acct.Salt)
	if err != nil {
		return nil, err
	}
	mk, err := vaultcrypto.MasterKey(password, salt, acct.KDF)
	if err != nil {
		return nil, err
	}
	wrap := vaultcrypto.Derive(mk, vaultcrypto.InfoWrap)
	ak, err := vaultcrypto.Open(wrap, acct.WrappedAccountKey, vaultcrypto.AADAccountKey())
	if err != nil {
		return nil, errors.New("wrong master password")
	}
	return ak, nil
}

// ---- commands

func cmdLogin(args []string) error {
	fs := flag.NewFlagSet("login", flag.ExitOnError)
	server := fs.String("server", "", "address of the PassZit server, e.g. https://vault.example.com")
	email := fs.String("email", "", "e-mail address of the account")
	_ = fs.Parse(args)
	c, err := loadConfig()
	if err != nil {
		return err
	}
	if *server == "" {
		*server = c.Server
	}
	if *server == "" {
		if *server, err = prompt("Server address: "); err != nil {
			return err
		}
	}
	u, err := url.Parse(strings.TrimSpace(*server))
	if err != nil || u.Host == "" || (u.Scheme != "https" && !(u.Scheme == "http" && (u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1"))) {
		return errors.New("the server address must start with https://")
	}
	srv := u.Scheme + "://" + u.Host
	if *email == "" {
		*email = c.Email
	}
	if *email == "" {
		if *email, err = prompt("E-mail address: "); err != nil {
			return err
		}
	}
	pw, err := promptSecret("Master password: ")
	if err != nil {
		return err
	}
	var pre struct {
		KDF  vaultcrypto.KDF `json:"kdf"`
		Salt string          `json:"salt"`
	}
	if err := call(srv, "", "POST", "/api/ext/prelogin", map[string]string{"email": *email}, &pre); err != nil {
		return err
	}
	salt, err := b64.DecodeString(pre.Salt)
	if err != nil {
		return err
	}
	mk, err := vaultcrypto.MasterKey(pw, salt, pre.KDF)
	if err != nil {
		return err
	}
	host, _ := os.Hostname()
	device := "PassZit CLI on " + host + " (" + runtime.GOOS + ")"
	var res struct {
		Next  string `json:"next"`
		Token string `json:"token"`
	}
	if err := call(srv, "", "POST", "/api/ext/login", map[string]string{"email": *email, "auth": b64.EncodeToString(vaultcrypto.Derive(mk, vaultcrypto.InfoAuth)), "device": device}, &res); err != nil {
		return err
	}
	if res.Next == "2fa" {
		code, err := prompt("Code from the authenticator app: ")
		if err != nil {
			return err
		}
		if err := call(srv, res.Token, "POST", "/api/ext/login/2fa", map[string]string{"code": code}, &res); err != nil {
			return err
		}
	}
	if c.Token != "" && c.Server == srv {
		_ = call(srv, c.Token, "POST", "/api/ext/logout", nil, nil)
	}
	*c = config{Server: srv, Email: *email, Token: res.Token, Device: device}
	if err := c.save(); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "Signed in to %s as %s. It shows as %q under My account → Active sessions.\n", srv, *email, device)
	return nil
}

func cmdUnlock(args []string) error {
	fs := flag.NewFlagSet("unlock", flag.ExitOnError)
	raw := fs.Bool("raw", false, "print only the session key")
	_ = fs.Parse(args)
	c, err := signedIn()
	if err != nil {
		return err
	}
	_ = os.Unsetenv("PASSZIT_SESSION")
	k, err := unlockKeys(c)
	if err != nil {
		return err
	}
	sk := vaultcrypto.Random(32)
	if c.SessionKey, err = vaultcrypto.Seal(sk, k.account, "passzit/cli-session/v1"); err != nil {
		return err
	}
	if err := c.save(); err != nil {
		return err
	}
	s := b64.EncodeToString(sk)
	if *raw {
		fmt.Println(s)
		return nil
	}
	fmt.Fprintln(os.Stderr, "Unlocked. Set this in your shell (passzit lock forgets it):")
	if runtime.GOOS == "windows" {
		fmt.Printf("$env:PASSZIT_SESSION=\"%s\"\n", s)
	} else {
		fmt.Printf("export PASSZIT_SESSION=\"%s\"\n", s)
	}
	return nil
}

func cmdLock() error {
	c, err := loadConfig()
	if err != nil {
		return err
	}
	c.SessionKey = ""
	if err := c.save(); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "Locked: the session key no longer opens the vault.")
	return nil
}

func cmdLogout() error {
	c, err := loadConfig()
	if err != nil {
		return err
	}
	if c.Token != "" {
		_ = call(c.Server, c.Token, "POST", "/api/ext/logout", nil, nil)
	}
	*c = config{Server: c.Server, Email: c.Email}
	if err := c.save(); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "Signed out.")
	return nil
}

func cmdStatus() error {
	c, err := loadConfig()
	if err != nil {
		return err
	}
	if c.Token == "" {
		fmt.Println("not signed in")
		return nil
	}
	state := "locked"
	if c.SessionKey != "" && os.Getenv("PASSZIT_SESSION") != "" {
		state = "unlocked (PASSZIT_SESSION)"
	}
	fmt.Printf("server  %s\naccount %s\ndevice  %s\nstate   %s\n", c.Server, c.Email, c.Device, state)
	return nil
}

// ---- items

type item struct {
	ID        string
	VaultID   string
	DeletedAt *time.Time
	Data      itemData
}

type itemData struct {
	Type  string `json:"type"`
	Name  string `json:"name"`
	Notes string `json:"notes"`
	Login *struct {
		Username string   `json:"username"`
		Password string   `json:"password"`
		URLs     []string `json:"urls"`
		TOTP     string   `json:"totp"`
	} `json:"login"`
	Connect *struct {
		Tool string `json:"tool"`
		Host string `json:"host"`
		Port int    `json:"port"`
	} `json:"connect"`
}

func loadItems(c *config, k *keys) ([]item, error) {
	var d struct {
		Vaults []struct {
			ID         string `json:"id"`
			Kind       string `json:"kind"`
			WrappedKey string `json:"wrapped_key"`
		} `json:"vaults"`
		Items []struct {
			ID        string     `json:"id"`
			VaultID   string     `json:"vault_id"`
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
	var out []item
	for _, it := range d.Items {
		key := vk[it.VaultID]
		if key == nil || it.DeletedAt != nil {
			continue
		}
		plain, err := vaultcrypto.Open(key, it.Data, vaultcrypto.AADItem(it.VaultID, it.ID))
		if err != nil {
			continue
		}
		var data itemData
		if json.Unmarshal(plain, &data) != nil || data.Type == "folder" {
			continue
		}
		out = append(out, item{ID: it.ID, VaultID: it.VaultID, Data: data})
	}
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i].Data.Name) < strings.ToLower(out[j].Data.Name) })
	return out, nil
}

func (it item) where() string {
	if it.Data.Login != nil && len(it.Data.Login.URLs) > 0 {
		return it.Data.Login.URLs[0]
	}
	if it.Data.Connect != nil && it.Data.Connect.Host != "" {
		return it.Data.Connect.Tool + " " + it.Data.Connect.Host
	}
	return ""
}

func (it item) user() string {
	if it.Data.Login != nil {
		return it.Data.Login.Username
	}
	return ""
}

func (it item) matches(q string) bool {
	q = strings.ToLower(q)
	return strings.Contains(strings.ToLower(it.Data.Name+"\n"+it.user()+"\n"+it.where()), q)
}

func cmdList(args []string) error {
	c, err := signedIn()
	if err != nil {
		return err
	}
	k, err := unlockKeys(c)
	if err != nil {
		return err
	}
	items, err := loadItems(c, k)
	if err != nil {
		return err
	}
	q := strings.Join(args, " ")
	for _, it := range items {
		if q == "" || it.matches(q) {
			fmt.Printf("%s  %-30s  %-28s  %s\n", it.ID[:8], it.Data.Name, it.user(), it.where())
		}
	}
	return nil
}

// find picks one item by id (or its first 8 characters), exact name, or a
// single match.
func find(items []item, q string) (item, error) {
	var exact, part []item
	for _, it := range items {
		if it.ID == q || (len(q) >= 8 && strings.HasPrefix(it.ID, q)) {
			return it, nil
		}
		if strings.EqualFold(it.Data.Name, q) {
			exact = append(exact, it)
		} else if it.matches(q) {
			part = append(part, it)
		}
	}
	if len(exact) == 1 {
		return exact[0], nil
	}
	if len(exact) == 0 && len(part) == 1 {
		return part[0], nil
	}
	cand := append(exact, part...)
	if len(cand) == 0 {
		return item{}, fmt.Errorf("no item matches %q", q)
	}
	var names []string
	for _, it := range cand {
		names = append(names, it.ID[:8]+" "+it.Data.Name)
	}
	return item{}, fmt.Errorf("%d items match %q; use the id:\n  %s", len(cand), q, strings.Join(names, "\n  "))
}

func cmdGet(args []string) error {
	if len(args) < 2 {
		return errors.New("usage: passzit get password|username|totp|notes|url|item NAME-OR-ID")
	}
	what, q := args[0], strings.Join(args[1:], " ")
	c, err := signedIn()
	if err != nil {
		return err
	}
	k, err := unlockKeys(c)
	if err != nil {
		return err
	}
	items, err := loadItems(c, k)
	if err != nil {
		return err
	}
	it, err := find(items, q)
	if err != nil {
		return err
	}
	l := it.Data.Login
	switch what {
	case "password":
		if l == nil || l.Password == "" {
			return errors.New("this item has no password")
		}
		fmt.Println(l.Password)
	case "username":
		if l == nil {
			return errors.New("this item has no user name")
		}
		fmt.Println(l.Username)
	case "totp":
		if l == nil || l.TOTP == "" {
			return errors.New("this item has no one-time code")
		}
		code, err := totpNow(l.TOTP, time.Now())
		if err != nil {
			return err
		}
		fmt.Println(code)
	case "notes":
		fmt.Println(it.Data.Notes)
	case "url":
		fmt.Println(it.where())
	case "item":
		b, _ := json.MarshalIndent(it.Data, "", "  ")
		fmt.Println(string(b))
	default:
		return fmt.Errorf("unknown field %q", what)
	}
	return nil
}

// totpNow computes the current code of a base32 secret or an otpauth:// URI.
func totpNow(s string, now time.Time) (string, error) {
	secret, digits, period, algo := s, 6, 30, "SHA1"
	if u, err := url.Parse(s); err == nil && u.Scheme == "otpauth" {
		q := u.Query()
		secret = q.Get("secret")
		if d, err := strconv.Atoi(q.Get("digits")); err == nil && d >= 6 && d <= 8 {
			digits = d
		}
		if p, err := strconv.Atoi(q.Get("period")); err == nil && p > 0 && p <= 300 {
			period = p
		}
		if a := strings.ToUpper(q.Get("algorithm")); a != "" {
			algo = a
		}
	}
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(strings.ReplaceAll(strings.TrimRight(secret, "="), " ", "")))
	if err != nil || len(key) == 0 {
		return "", errors.New("the one-time code secret is not valid base32")
	}
	var h func() hash.Hash
	switch algo {
	case "SHA256":
		h = sha256.New
	case "SHA512":
		h = sha512.New
	default:
		h = sha1.New
	}
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(now.Unix()/int64(period))) // #nosec G115 -- time after 1970
	m := hmac.New(h, key)
	m.Write(msg[:])
	sum := m.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	v := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	mod := uint32(1)
	for i := 0; i < digits; i++ {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", digits, v%mod), nil
}

func cmdGenerate(args []string) error {
	fs := flag.NewFlagSet("generate", flag.ExitOnError)
	length := fs.Int("length", 20, "length of a password")
	words := fs.Int("words", 0, "a passphrase of this many words instead (EFF list, needs the server)")
	_ = fs.Parse(args)
	if *words > 0 {
		return errors.New("passphrases: use the generator of the web vault or the extension")
	}
	if *length < 8 || *length > 128 {
		return errors.New("the length must be 8 to 128")
	}
	const sets = "abcdefghijkmnopqrstuvwxyz" + "ABCDEFGHJKLMNPQRSTUVWXYZ" + "23456789" + "!#$%&*+-=?@_"
	var b strings.Builder
	for i := 0; i < *length; i++ {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(sets))))
		if err != nil {
			return err
		}
		b.WriteByte(sets[n.Int64()])
	}
	fmt.Println(b.String())
	return nil
}
