package web

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/max-zit/passzit/internal/store"
)

// Parsers of what the server reads from outside: return addresses, signed
// SSO state, identity provider metadata, uploaded certificates and the JSON
// requests of the web vault, the browser extension and the command line.

func FuzzSafeNext(f *testing.F) {
	for _, s := range []string{"/vault", "//evil.example", "/\\evil", "/%0d%0aSet-Cookie", "https://x", "/settings?x=1#y"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, p string) {
		n := safeNext(p)
		if !strings.HasPrefix(n, "/") || strings.HasPrefix(n, "//") || strings.HasPrefix(n, "/\\") || strings.ContainsAny(n, "\r\n\t\x00") {
			t.Fatalf("safeNext(%q) = %q leaves the site", p, n)
		}
		if u, err := urlPath(p); err == nil {
			_ = safeNext(u)
		}
	})
}

func FuzzSSOState(f *testing.F) {
	good := signState(time.Hour, "oidc", "nonce", "/vault")
	f.Add(good)
	f.Add("a.b")
	f.Add(good + "x")
	f.Fuzz(func(t *testing.T, tok string) {
		v, ok := parseState(tok)
		if ok && tok != good && strings.Join(v, "\x00") != "oidc\x00nonce\x00/vault" {
			t.Fatalf("forged state %q accepted: %q", tok, v)
		}
	})
}

func FuzzIDPMetadata(f *testing.F) {
	f.Add([]byte(`<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example/"><IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example/sso"/></IDPSSODescriptor></EntityDescriptor>`))
	f.Add([]byte(`<EntitiesDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"></EntitiesDescriptor>`))
	f.Add([]byte(`<!DOCTYPE x [<!ENTITY a "aaaa">]><x>&a;</x>`))
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = parseIDPMetadata(b)
	})
}

func FuzzCertificateUpload(f *testing.F) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "vault.example.com"}, DNSNames: []string{"vault.example.com"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	kd, _ := x509.MarshalPKCS8PrivateKey(k)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kd})
	f.Add(certPEM, keyPEM, "vault.example.com")
	f.Add([]byte("-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n"), keyPEM, "")
	f.Fuzz(func(t *testing.T, c, key []byte, host string) {
		_, _ = parseKeyPair(c, key, host, time.Now())
	})
}

func FuzzBrowserOf(f *testing.F) {
	f.Add("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0 Safari/537.36 Edg/140.0")
	f.Fuzz(func(t *testing.T, ua string) {
		if b := browserOf(ua); len(b) > 40 {
			t.Fatalf("browserOf gave %q", b)
		}
	})
}

// FuzzRequests decodes request bodies the way every API handler does (JSON
// only, size limit, unknown fields refused) into the request types of the
// vault, the extension, the command line, sharing and access requests.
func FuzzRequests(f *testing.F) {
	for _, s := range []string{
		`{"email":"a@b.c","auth":"x","device":"Chrome · Windows"}`,
		`{"vault_id":"6302efd8-04e6-405d-9293-6dc2d8dce847","data":"AQ","revision":3}`,
		`{"user_id":2,"wrapped_key":"AQ","rights":"view","expires_at":"2026-12-01T00:00:00Z"}`,
		`{"vault_id":"","asked_id":1,"rights":"edit","hours":4,"reason":"backup"}`,
		`{"approve":true,"vault_id":"x"}`,
		`{"action":"copy","via":"console"}`,
		`{"id":"x","data":"AQ","max_views":1,"hours":1}`,
		`{"a":` + strings.Repeat("[", 5000),
	} {
		f.Add([]byte(s), uint8(0))
	}
	f.Fuzz(func(t *testing.T, body []byte, kind uint8) {
		targets := []func() any{
			func() any { return new(extLoginReq) }, func() any { return new(putItemReq) }, func() any { return new(store.MemberChange) },
			func() any { return new(store.NewAccessRequest) }, func() any { return new(decideReq) }, func() any { return new(accessReq) },
			func() any { return new(createSendReq) }, func() any { return new(createVaultReq) },
		}
		v := targets[int(kind)%len(targets)]()
		r := httptest.NewRequest(http.MethodPost, "/api/x", bytes.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		if !readJSON(w, r, 64<<10, v) && w.Code != http.StatusBadRequest {
			t.Fatalf("refused with %d", w.Code)
		}
	})
}
