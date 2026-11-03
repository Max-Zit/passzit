package web

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"log/slog"
	"math/big"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/letsencrypt/pebble/v2/ca"
	"github.com/letsencrypt/pebble/v2/db"
	"github.com/letsencrypt/pebble/v2/va"
	"github.com/letsencrypt/pebble/v2/wfe"
)

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newTestCA(t *testing.T) *testCA {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test CA"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return &testCA{c, key}
}

func (ca *testCA) leaf(t *testing.T, names []string, from, to time.Time) (certPEM, keyPEM []byte) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: names[0]},
		NotBefore: from, NotAfter: to, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	for _, n := range names {
		if ip := net.ParseIP(n); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, n)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	kb, _ := x509.MarshalECPrivateKey(key)
	return pemEncode([][]byte{der, ca.cert.Raw}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb})
}

func TestParseKeyPair(t *testing.T) {
	ca := newTestCA(t)
	now := time.Now()
	c, k := ca.leaf(t, []string{"vault.example.com", "10.0.0.5"}, now.Add(-time.Hour), now.Add(time.Hour))
	if _, err := parseKeyPair(c, k, "vault.example.com", now); err != nil {
		t.Fatal(err)
	}
	if _, err := parseKeyPair(c, k, "10.0.0.5", now); err != nil {
		t.Fatal(err)
	}
	if _, err := parseKeyPair(c, k, "other.example.com", now); err == nil || !strings.Contains(err.Error(), "not valid for") {
		t.Errorf("wrong name: %v", err)
	}
	if _, err := parseKeyPair(c, k, "vault.example.com", now.Add(2*time.Hour)); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Errorf("expired: %v", err)
	}
	_, k2 := ca.leaf(t, []string{"vault.example.com"}, now.Add(-time.Hour), now.Add(time.Hour))
	if _, err := parseKeyPair(c, k2, "", now); err == nil {
		t.Error("key of another certificate accepted")
	}
}

func selfSigned(t *testing.T) tls.Certificate {
	ca := newTestCA(t)
	c, k := ca.leaf(t, []string{"localhost"}, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	pair, err := tls.X509KeyPair(c, k)
	if err != nil {
		t.Fatal(err)
	}
	return pair
}

func TestCertsServeAndRedirect(t *testing.T) {
	c := NewCerts(t.TempDir(), selfSigned(t), slog.New(slog.DiscardHandler))
	var mu sync.Mutex
	var port80 string
	c.listen = func(network, _ string) (net.Listener, error) {
		ln, err := net.Listen(network, "127.0.0.1:0")
		if err == nil {
			mu.Lock()
			port80 = ln.Addr().String()
			mu.Unlock()
		}
		return ln, err
	}
	c.port = "8443"
	got, _ := c.GetCertificate(nil)
	if got != c.self {
		t.Fatal("self-signed certificate not served first")
	}
	ca := newTestCA(t)
	cp, kp := ca.leaf(t, []string{"vault.example.com"}, time.Now().Add(-time.Hour), time.Now().Add(90*24*time.Hour))
	if err := c.saveCert(cp, kp); err != nil {
		t.Fatal(err)
	}
	if err := c.apply(CertSettings{Mode: "upload", Hostname: "vault.example.com", RedirectHTTP: true}); err != nil {
		t.Fatal(err)
	}
	got, _ = c.GetCertificate(nil)
	if got == c.self || got.Leaf.DNSNames[0] != "vault.example.com" {
		t.Fatal("trusted certificate not served")
	}
	cl := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	mu.Lock()
	addr := port80
	mu.Unlock()
	resp, err := cl.Get("http://" + addr + "/vault?x=1")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMovedPermanently || resp.Header.Get("Location") != "https://vault.example.com:8443/vault?x=1" {
		t.Errorf("redirect: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	c.mu.Lock()
	c.acmeKeys = map[string]string{"tok": "tok.thumb"}
	c.mu.Unlock()
	resp, _ = cl.Get("http://" + addr + "/.well-known/acme-challenge/tok")
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(b) != "tok.thumb" {
		t.Errorf("challenge answer %q", b)
	}
	// back to the own certificate: port 80 closes
	if err := c.apply(CertSettings{Mode: "self"}); err != nil {
		t.Fatal(err)
	}
	if got, _ := c.GetCertificate(nil); got != c.self {
		t.Error("still the trusted certificate")
	}
	if _, err := net.DialTimeout("tcp", addr, time.Second); err == nil {
		t.Error("port 80 still open")
	}
}

// startPebble runs Let's Encrypt's test CA in the process; checks always pass.
func startPebble(t *testing.T) *httptest.Server {
	t.Setenv("PEBBLE_VA_ALWAYS_VALID", "1")
	t.Setenv("PEBBLE_VA_NOSLEEP", "1")
	t.Setenv("PEBBLE_WFE_NONCEREJECT", "0")
	logger := log.New(io.Discard, "", 0)
	store := db.NewMemoryStore()
	c := ca.New(logger, store, "", "ecdsa", 0, 1, map[string]ca.Profile{"default": {Description: "default"}})
	v := va.New(logger, 5002, 5001, false, "", store)
	w := wfe.New(logger, store, v, c, nil, false, false, 0, 0)
	ts := httptest.NewTLSServer(w.Handler())
	t.Cleanup(ts.Close)
	return ts
}

func TestACMEWithPebble(t *testing.T) {
	ts := startPebble(t)
	c := NewCerts(t.TempDir(), selfSigned(t), slog.New(slog.DiscardHandler))
	c.dnsDelay = time.Millisecond
	ctx := context.Background()
	cfg := CertSettings{Mode: "acme", Hostname: "vault.example.com", RedirectHTTP: true, ACMEEmail: "admin@example.com",
		Challenge: "http", ACMEDirectory: ts.URL + "/dir"}
	if err := c.obtainACME(ctx, cfg, "", ts.Client()); err != nil {
		t.Fatal(err)
	}
	if k := c.loadCert(); k == nil || k.Leaf.DNSNames[0] != "vault.example.com" || !strings.Contains(k.Leaf.Issuer.CommonName, "Pebble") {
		t.Fatalf("certificate: %+v", k)
	}
	// DNS check through a fake Cloudflare API
	var records []string
	var mu sync.Mutex
	cf := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.Header.Get("Authorization") != "Bearer cf-token" {
			_ = json.NewEncoder(w).Encode(map[string]any{"success": false, "errors": []map[string]string{{"message": "bad token"}}})
			return
		}
		switch {
		case r.Method == "GET" && r.URL.Path == "/zones":
			res := []map[string]string{}
			if r.URL.Query().Get("name") == "example.com" {
				res = append(res, map[string]string{"id": "z1"})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": res})
		case r.Method == "POST" && r.URL.Path == "/zones/z1/dns_records":
			var rec map[string]any
			_ = json.NewDecoder(r.Body).Decode(&rec)
			records = append(records, fmt.Sprint("add ", rec["name"]))
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": map[string]string{"id": "r1"}})
		case r.Method == "DELETE" && r.URL.Path == "/zones/z1/dns_records/r1":
			records = append(records, "delete")
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": map[string]string{"id": "r1"}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer cf.Close()
	c.cfBase = cf.URL
	cfg.Hostname, cfg.Challenge = "intern.example.com", "cloudflare"
	if err := c.obtainACME(ctx, cfg, "cf-token", ts.Client()); err != nil {
		t.Fatal(err)
	}
	if k := c.loadCert(); k == nil || k.Leaf.DNSNames[0] != "intern.example.com" {
		t.Fatal("no certificate from the DNS check")
	}
	if strings.Join(records, ",") != "add _acme-challenge.intern.example.com,delete" {
		t.Errorf("Cloudflare calls: %v", records)
	}
	cfg.Hostname = "other.example.com"
	if err := c.obtainACME(ctx, cfg, "wrong", ts.Client()); err == nil || !strings.Contains(err.Error(), "bad token") {
		t.Errorf("bad Cloudflare token: %v", err)
	}
}

func TestCertificatePage(t *testing.T) {
	e := newEnv(t)
	admin := e.setupAdmin()
	e.srv.Certs = NewCerts(t.TempDir(), selfSigned(t), slog.New(slog.DiscardHandler))
	if code, page := admin.get("/settings/certificate"); code != http.StatusOK || !strings.Contains(page, "self-signed") {
		t.Fatalf("certificate page: %d", code)
	}
	ca := newTestCA(t)
	cp, kp := ca.leaf(t, []string{"192.168.1.10"}, time.Now().Add(-time.Hour), time.Now().Add(90*24*time.Hour))
	post := func(fields map[string]string) int {
		var body bytes.Buffer
		mw := multipart.NewWriter(&body)
		for k, v := range fields {
			_ = mw.WriteField(k, v)
		}
		_ = mw.Close()
		req, _ := http.NewRequest(http.MethodPost, e.ts.URL+"/settings/certificate", &body)
		req.Header.Set("Content-Type", mw.FormDataContentType())
		req.Header.Set("Origin", e.ts.URL)
		resp, err := admin.hc.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if code := post(map[string]string{"mode": "upload", "hostname": "other.example.com", "cert_pem": string(cp), "key_pem": string(kp)}); code != http.StatusBadRequest {
		t.Fatalf("certificate for another name: %d", code)
	}
	if code := post(map[string]string{"mode": "upload", "hostname": "192.168.1.10", "cert_pem": string(cp), "key_pem": string(kp)}); code != http.StatusSeeOther {
		t.Fatalf("upload: %d", code)
	}
	if got, _ := e.srv.Certs.GetCertificate(nil); got == e.srv.Certs.self {
		t.Fatal("the uploaded certificate is not served")
	}
	var c CertSettings
	if err := e.st.GetSetting(t.Context(), settingCert, &c); err != nil || c.Mode != "upload" || c.Hostname != "192.168.1.10" {
		t.Fatalf("saved settings: %+v %v", c, err)
	}
	if code := post(map[string]string{"mode": "self"}); code != http.StatusSeeOther {
		t.Fatalf("back to self-signed: %d", code)
	}
	if got, _ := e.srv.Certs.GetCertificate(nil); got != e.srv.Certs.self {
		t.Fatal("still the uploaded certificate")
	}
}
