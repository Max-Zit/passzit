package vaultcrypto

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"golang.org/x/crypto/argon2"
)

// TestArgon2Reference checks the Argon2id building block against a test
// vector of the reference implementation (phc-winner-argon2, src/test.c).
func TestArgon2Reference(t *testing.T) {
	a := argon2.IDKey([]byte("password"), []byte("somesalt"), 2, 65536, 1, 32)
	want := "09316115d5cf24ed5a15a31a3ba326e5cf32edc24702987c02b6566f61913cf7"
	if hex.EncodeToString(a) != want {
		t.Fatalf("argon2id = %x, want %s", a, want)
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestVectors(t *testing.T) {
	v := Vectors
	salt := mustHex(t, v.SaltHex)
	mk, err := MasterKey(v.Password, salt, v.KDF)
	if err != nil {
		t.Fatal(err)
	}
	pk, err := MasterKey(v.Password, salt, KDF{Alg: "pbkdf2-sha256", T: 600_000})
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := sealNonce(mustHex(t, v.KeyHex), []byte(v.Plain), v.AAD, mustHex(t, v.NonceHex))
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{
		"master": hex.EncodeToString(mk), "auth": hex.EncodeToString(Derive(mk, InfoAuth)), "wrap": hex.EncodeToString(Derive(mk, InfoWrap)),
		"pbkdf2": hex.EncodeToString(pk), "sealed": sealed,
	}
	want := map[string]string{"master": v.MasterHex, "auth": v.AuthHex, "wrap": v.Wrap, "pbkdf2": v.PBKDF2Master, "sealed": v.Sealed}
	for k, w := range want {
		if got[k] != w {
			t.Errorf("%s = %s, want %s", k, got[k], w)
		}
	}
}

func TestSealOpen(t *testing.T) {
	k := Random(32)
	s, err := Seal(k, []byte("secret"), "a")
	if err != nil {
		t.Fatal(err)
	}
	if p, err := Open(k, s, "a"); err != nil || string(p) != "secret" {
		t.Fatalf("open = %q, %v", p, err)
	}
	if _, err := Open(k, s, "b"); err != ErrDecrypt {
		t.Fatal("another AAD must fail")
	}
	if _, err := Open(Random(32), s, "a"); err != ErrDecrypt {
		t.Fatal("another key must fail")
	}
	raw, _ := B64.DecodeString(s)
	raw[len(raw)-1] ^= 1
	if _, err := Open(k, B64.EncodeToString(raw), "a"); err != ErrDecrypt {
		t.Fatal("tampering must fail")
	}
	s2, _ := Seal(k, []byte("secret"), "a")
	if s == s2 {
		t.Fatal("nonces must differ")
	}
}

func TestSealTo(t *testing.T) {
	pub, priv, err := NewKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	s, err := SealTo(pub, []byte("vault key"), "x")
	if err != nil {
		t.Fatal(err)
	}
	p, err := OpenSealed(priv, s, "x")
	if err != nil || string(p) != "vault key" {
		t.Fatalf("open sealed = %q, %v", p, err)
	}
	_, other, _ := NewKeyPair()
	if _, err := OpenSealed(other, s, "x"); err == nil {
		t.Fatal("another private key must fail")
	}
	if _, err := OpenSealed(priv, s, "y"); err == nil {
		t.Fatal("another AAD must fail")
	}
	if fp := Fingerprint(pub); len(strings.Fields(fp)) != 10 {
		t.Fatalf("fingerprint %q", fp)
	}
}

func TestRecoveryKey(t *testing.T) {
	k := NewRecoveryKey()
	if len(k) != 39 || strings.Count(k, "-") != 7 {
		t.Fatalf("recovery key %q", k)
	}
	raw, err := ParseRecoveryKey(strings.ToLower(strings.ReplaceAll(k, "-", " ")))
	if err != nil || FormatRecoveryKey(raw) != k {
		t.Fatalf("parse %q: %v", k, err)
	}
	if _, err := ParseRecoveryKey("ABCD"); err == nil {
		t.Fatal("short key accepted")
	}
}

func TestKDF(t *testing.T) {
	if DefaultKDF.Validate() != nil {
		t.Fatal("default invalid")
	}
	for _, k := range []KDF{{Alg: "argon2id", M: 1024, T: 3, P: 1}, {Alg: "pbkdf2-sha256", T: 1000}, {Alg: "md5"}} {
		if k.Validate() == nil {
			t.Errorf("%+v accepted", k)
		}
	}
	if !DefaultKDF.Stronger(KDF{Alg: "argon2id", M: 19 * 1024, T: 2, P: 1}) || DefaultKDF.Stronger(DefaultKDF) {
		t.Fatal("Stronger")
	}
	if _, err := MasterKey("x", []byte("salt"), KDF{Alg: "argon2id", M: 64, T: 1, P: 1}); err == nil {
		t.Fatal("weak parameters accepted")
	}
	a, _ := MasterKey("é", []byte("0123456789abcdef"), KDF{Alg: "argon2id", M: 19 * 1024, T: 2, P: 1})
	b, _ := MasterKey("é", []byte("0123456789abcdef"), KDF{Alg: "argon2id", M: 19 * 1024, T: 2, P: 1})
	if !bytes.Equal(a, b) {
		t.Fatal("passwords must be NFC-normalised")
	}
}
