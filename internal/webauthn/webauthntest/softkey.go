// Package webauthntest is a software security key for tests: it answers
// registrations and sign-ins like a real authenticator (ES256 or EdDSA,
// attestation "none").
package webauthntest

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"

	"github.com/max-zit/passzit/internal/webauthn"
)

var b64 = base64.RawURLEncoding

// head encodes a CBOR head; test values are small, so the conversions
// below cannot overflow.
func head(major byte, n int) []byte {
	switch {
	case n < 24:
		return []byte{major<<5 | byte(n)} // #nosec G115 -- n < 24
	case n < 256:
		return []byte{major<<5 | 24, byte(n)} // #nosec G115 -- n < 256
	default:
		return []byte{major<<5 | 25, byte(n >> 8), byte(n)} // #nosec G115 -- test sizes < 65536
	}
}

func cInt(v int64) []byte {
	if v >= 0 {
		return head(0, int(v))
	}
	return head(1, int(-1-v))
}

func cBytes(b []byte) []byte { return append(head(2, len(b)), b...) }
func cText(s string) []byte  { return append(head(3, len(s)), s...) }

type kv struct{ k, v []byte }

func cMap(items ...kv) []byte {
	out := head(5, len(items))
	for _, it := range items {
		out = append(append(out, it.k...), it.v...)
	}
	return out
}

// Key is a software authenticator with one credential.
type Key struct {
	Alg   int
	ec    *ecdsa.PrivateKey
	ed    ed25519.PrivateKey
	ID    []byte
	Count uint32
}

// New makes a key for an algorithm (webauthn.AlgES256 or AlgEdDSA).
func New(alg int) *Key {
	k := &Key{Alg: alg, ID: make([]byte, 16)}
	_, _ = rand.Read(k.ID)
	if alg == webauthn.AlgES256 {
		k.ec, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	} else {
		_, k.ed, _ = ed25519.GenerateKey(rand.Reader)
	}
	return k
}

func (k *Key) cose() []byte {
	if k.Alg == webauthn.AlgES256 {
		raw, _ := k.ec.PublicKey.Bytes()
		return cMap(kv{cInt(1), cInt(2)}, kv{cInt(3), cInt(webauthn.AlgES256)}, kv{cInt(-1), cInt(1)}, kv{cInt(-2), cBytes(raw[1:33])}, kv{cInt(-3), cBytes(raw[33:])})
	}
	return cMap(kv{cInt(1), cInt(1)}, kv{cInt(3), cInt(webauthn.AlgEdDSA)}, kv{cInt(-1), cInt(6)}, kv{cInt(-2), cBytes(k.ed.Public().(ed25519.PublicKey))})
}

func (k *Key) authData(rpID string, attested bool) []byte {
	h := sha256.Sum256([]byte(rpID))
	b := append([]byte(nil), h[:]...)
	flags := byte(0x01 | 0x04)
	if attested {
		flags |= 0x40
	}
	b = append(b, flags)
	b = binary.BigEndian.AppendUint32(b, k.Count)
	if attested {
		b = append(b, make([]byte, 16)...)
		b = binary.BigEndian.AppendUint16(b, uint16(len(k.ID))) // #nosec G115 -- 16 bytes
		b = append(b, k.ID...)
		b = append(b, k.cose()...)
	}
	return b
}

func clientJSON(typ, challenge, origin string) []byte {
	b, _ := json.Marshal(map[string]string{"type": typ, "challenge": challenge, "origin": origin})
	return b
}

// Register answers a registration (challenge as the server sent it, base64url).
func (k *Key) Register(rpID, origin, challenge string) webauthn.Registration {
	ao := cMap(kv{cText("fmt"), cText("none")}, kv{cText("attStmt"), cMap()}, kv{cText("authData"), cBytes(k.authData(rpID, true))})
	return webauthn.Registration{ID: b64.EncodeToString(k.ID), ClientDataJSON: b64.EncodeToString(clientJSON("webauthn.create", challenge, origin)), AttestationObject: b64.EncodeToString(ao)}
}

// SignIn answers a sign-in.
func (k *Key) SignIn(rpID, origin, challenge string) webauthn.Assertion {
	k.Count++
	ad := k.authData(rpID, false)
	cd := clientJSON("webauthn.get", challenge, origin)
	h := sha256.Sum256(cd)
	msg := append(append([]byte(nil), ad...), h[:]...)
	var sig []byte
	if k.Alg == webauthn.AlgES256 {
		d := sha256.Sum256(msg)
		sig, _ = ecdsa.SignASN1(rand.Reader, k.ec, d[:])
	} else {
		sig, _ = k.ed.Sign(rand.Reader, msg, crypto.Hash(0))
	}
	return webauthn.Assertion{ID: b64.EncodeToString(k.ID), ClientDataJSON: b64.EncodeToString(cd), AuthenticatorData: b64.EncodeToString(ad), Signature: b64.EncodeToString(sig)}
}
