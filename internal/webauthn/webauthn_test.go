package webauthn

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"testing"
)

// ---- a software authenticator for the tests

func encHead(major byte, n int) []byte {
	switch {
	case n < 24:
		return []byte{major<<5 | byte(n)}
	case n < 256:
		return []byte{major<<5 | 24, byte(n)}
	default:
		return []byte{major<<5 | 25, byte(n >> 8), byte(n)}
	}
}

func encInt(v int64) []byte {
	if v >= 0 {
		return encHead(0, int(v))
	}
	return encHead(1, int(-1-v))
}

func encBytes(b []byte) []byte { return append(encHead(2, len(b)), b...) }
func encText(s string) []byte  { return append(encHead(3, len(s)), s...) }

type kv struct{ k, v []byte }

func encMap(items ...kv) []byte {
	out := encHead(5, len(items))
	for _, it := range items {
		out = append(append(out, it.k...), it.v...)
	}
	return out
}

type softKey struct {
	alg  int
	ec   *ecdsa.PrivateKey
	ed   ed25519.PrivateKey
	id   []byte
	sign uint32
}

func newSoftKey(t *testing.T, alg int) *softKey {
	k := &softKey{alg: alg, id: make([]byte, 16)}
	_, _ = rand.Read(k.id)
	var err error
	if alg == AlgES256 {
		k.ec, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	} else {
		_, k.ed, err = ed25519.GenerateKey(rand.Reader)
	}
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func (k *softKey) cose() []byte {
	if k.alg == AlgES256 {
		raw, _ := k.ec.PublicKey.Bytes()
		return encMap(kv{encInt(1), encInt(2)}, kv{encInt(3), encInt(AlgES256)}, kv{encInt(-1), encInt(1)}, kv{encInt(-2), encBytes(raw[1:33])}, kv{encInt(-3), encBytes(raw[33:])})
	}
	return encMap(kv{encInt(1), encInt(1)}, kv{encInt(3), encInt(AlgEdDSA)}, kv{encInt(-1), encInt(6)}, kv{encInt(-2), encBytes(k.ed.Public().(ed25519.PublicKey))})
}

func (k *softKey) authData(rpID string, flags byte, attested bool) []byte {
	h := sha256.Sum256([]byte(rpID))
	b := append([]byte(nil), h[:]...)
	b = append(b, flags)
	b = binary.BigEndian.AppendUint32(b, k.sign)
	if attested {
		b = append(b, make([]byte, 16)...) // aaguid
		b = binary.BigEndian.AppendUint16(b, uint16(len(k.id)))
		b = append(b, k.id...)
		b = append(b, k.cose()...)
	}
	return b
}

func clientJSON(typ string, challenge []byte, origin string) []byte {
	b, _ := json.Marshal(clientData{Type: typ, Challenge: B64.EncodeToString(challenge), Origin: origin})
	return b
}

func (k *softKey) register(rpID, origin string, challenge []byte) Registration {
	ad := k.authData(rpID, flagUP|flagUV|flagAT, true)
	ao := encMap(kv{encText("fmt"), encText("none")}, kv{encText("attStmt"), encMap()}, kv{encText("authData"), encBytes(ad)})
	return Registration{ID: B64.EncodeToString(k.id), ClientDataJSON: B64.EncodeToString(clientJSON("webauthn.create", challenge, origin)), AttestationObject: B64.EncodeToString(ao)}
}

func (k *softKey) assert(rpID, origin string, challenge []byte) Assertion {
	k.sign++
	ad := k.authData(rpID, flagUP|flagUV, false)
	cd := clientJSON("webauthn.get", challenge, origin)
	h := sha256.Sum256(cd)
	msg := append(append([]byte(nil), ad...), h[:]...)
	var sig []byte
	if k.alg == AlgES256 {
		d := sha256.Sum256(msg)
		sig, _ = ecdsa.SignASN1(rand.Reader, k.ec, d[:])
	} else {
		sig, _ = k.ed.Sign(rand.Reader, msg, crypto.Hash(0))
	}
	return Assertion{ID: B64.EncodeToString(k.id), ClientDataJSON: B64.EncodeToString(cd), AuthenticatorData: B64.EncodeToString(ad), Signature: B64.EncodeToString(sig)}
}

func TestRegisterAndSignIn(t *testing.T) {
	const rp, origin = "vault.example.com", "https://vault.example.com"
	origins := []string{origin}
	for _, alg := range []int{AlgES256, AlgEdDSA} {
		k := newSoftKey(t, alg)
		ch := []byte("registration-challenge-32-bytes!")
		cred, err := VerifyRegistration(k.register(rp, origin, ch), ch, rp, origins)
		if err != nil || cred.Alg != alg {
			t.Fatalf("alg %d: registration: %v", alg, err)
		}
		// refused registrations
		if _, err := VerifyRegistration(k.register(rp, origin, ch), []byte("another challenge"), rp, origins); err == nil {
			t.Error("wrong challenge accepted")
		}
		if _, err := VerifyRegistration(k.register(rp, "https://evil.example", ch), ch, rp, origins); err == nil {
			t.Error("wrong origin accepted")
		}
		if _, err := VerifyRegistration(k.register("evil.example", origin, ch), ch, rp, origins); err == nil {
			t.Error("wrong relying party accepted")
		}
		// sign-ins
		ch2 := []byte("sign-in-challenge-32-bytes-long!")
		n, err := VerifyAssertion(k.assert(rp, origin, ch2), *cred, ch2, rp, origins)
		if err != nil || n != 1 {
			t.Fatalf("alg %d: sign-in: %v", alg, err)
		}
		cred.SignCount = n
		as := k.assert(rp, origin, ch2)
		if _, err := VerifyAssertion(as, *cred, []byte("old challenge"), rp, origins); err == nil {
			t.Error("replayed challenge accepted")
		}
		bad := as
		sig, _ := B64.DecodeString(bad.Signature)
		sig[len(sig)-1] ^= 1
		bad.Signature = B64.EncodeToString(sig)
		if _, err := VerifyAssertion(bad, *cred, ch2, rp, origins); err == nil {
			t.Error("wrong signature accepted")
		}
		cred.SignCount = 100 // a cloned key with a lower counter
		if _, err := VerifyAssertion(as, *cred, ch2, rp, origins); err == nil {
			t.Error("going back of the counter accepted")
		}
		other := newSoftKey(t, alg)
		other.id = k.id
		cred.SignCount = 0
		if _, err := VerifyAssertion(other.assert(rp, origin, ch2), *cred, ch2, rp, origins); err == nil {
			t.Error("another key with the same id accepted")
		}
	}
}

func TestCBORLimits(t *testing.T) {
	for _, b := range [][]byte{{0x5f}, {0x9f}, {0xbf}, {0x5a, 0xff, 0xff, 0xff, 0xff}, {0xf9, 0, 0}, {0xc1, 0}, {}} {
		if _, _, err := decodeCBOR(b); err == nil {
			t.Errorf("accepted % x", b)
		}
	}
	deep := make([]byte, 0, 40)
	for i := 0; i < 30; i++ {
		deep = append(deep, 0x81)
	}
	deep = append(deep, 0)
	if _, _, err := decodeCBOR(deep); err == nil {
		t.Error("too deep nesting accepted")
	}
}
