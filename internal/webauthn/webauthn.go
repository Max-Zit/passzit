package webauthn

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"math/big"
)

// B64 is the encoding of binary values in the browser API (base64url
// without padding).
var B64 = base64.RawURLEncoding

// COSE algorithms PassZit accepts.
const (
	AlgES256 = -7
	AlgEdDSA = -8
	AlgRS256 = -257
)

// Algorithms in the order the browser should prefer them.
var Algorithms = []int{AlgES256, AlgEdDSA, AlgRS256}

// Authenticator data flags.
const (
	flagUP = 0x01 // user present
	flagUV = 0x04 // user verified
	flagAT = 0x40 // attested credential data included
)

// Credential is a registered security key or passkey.
type Credential struct {
	ID        []byte // credential id
	PublicKey []byte // PKIX (DER) public key
	Alg       int
	SignCount uint32
}

type clientData struct {
	Type      string `json:"type"`
	Challenge string `json:"challenge"`
	Origin    string `json:"origin"`
}

// checkClientData verifies the type, the challenge and the origin.
func checkClientData(raw []byte, typ string, challenge []byte, origins []string) error {
	var c clientData
	if err := json.Unmarshal(raw, &c); err != nil {
		return errors.New("unreadable client data")
	}
	if c.Type != typ {
		return errors.New("wrong client data type")
	}
	got, err := B64.DecodeString(c.Challenge)
	if err != nil || len(challenge) == 0 || subtle.ConstantTimeCompare(got, challenge) != 1 {
		return errors.New("wrong challenge")
	}
	for _, o := range origins {
		if c.Origin == o {
			return nil
		}
	}
	return errors.New("wrong origin " + c.Origin)
}

type authData struct {
	rpIDHash  []byte
	flags     byte
	signCount uint32
	credID    []byte
	coseKey   []byte
}

func parseAuthData(b []byte, wantAttested bool) (*authData, error) {
	if len(b) < 37 {
		return nil, errors.New("authenticator data too short")
	}
	a := &authData{rpIDHash: b[:32], flags: b[32], signCount: binary.BigEndian.Uint32(b[33:37])}
	rest := b[37:]
	if a.flags&flagAT != 0 {
		if len(rest) < 18 {
			return nil, errors.New("attested data too short")
		}
		n := int(binary.BigEndian.Uint16(rest[16:18]))
		rest = rest[18:]
		if n == 0 || n > 1023 || len(rest) < n {
			return nil, errors.New("bad credential id")
		}
		a.credID = rest[:n]
		rest = rest[n:]
		_, after, err := decodeCBOR(rest)
		if err != nil {
			return nil, err
		}
		a.coseKey = rest[:len(rest)-len(after)]
	} else if wantAttested {
		return nil, errors.New("no credential in the registration")
	}
	return a, nil
}

func intOf(m map[any]any, k int64) (int64, bool) {
	v, ok := m[k].(int64)
	return v, ok
}

func bytesOf(m map[any]any, k int64) []byte {
	v, _ := m[k].([]byte)
	return v
}

// parseCOSEKey turns a COSE key into a PKIX public key and its algorithm.
func parseCOSEKey(b []byte) ([]byte, int, error) {
	v, rest, err := decodeCBOR(b)
	if err != nil || len(rest) != 0 {
		return nil, 0, errors.New("unreadable public key")
	}
	m, ok := v.(map[any]any)
	if !ok {
		return nil, 0, errors.New("unreadable public key")
	}
	kty, _ := intOf(m, 1)
	alg, _ := intOf(m, 3)
	var pub any
	switch {
	case kty == 2 && alg == AlgES256:
		crv, _ := intOf(m, -1)
		x, y := bytesOf(m, -2), bytesOf(m, -3)
		if crv != 1 || len(x) != 32 || len(y) != 32 {
			return nil, 0, errors.New("unsupported EC key")
		}
		raw := append(append([]byte{4}, x...), y...)
		k, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), raw)
		if err != nil {
			return nil, 0, errors.New("the EC key is not on the curve")
		}
		pub = k
	case kty == 1 && alg == AlgEdDSA:
		crv, _ := intOf(m, -1)
		x := bytesOf(m, -2)
		if crv != 6 || len(x) != ed25519.PublicKeySize {
			return nil, 0, errors.New("unsupported OKP key")
		}
		pub = ed25519.PublicKey(x)
	case kty == 3 && alg == AlgRS256:
		n, e := bytesOf(m, -1), bytesOf(m, -2)
		if len(n) < 256 || len(e) == 0 || len(e) > 4 {
			return nil, 0, errors.New("unsupported RSA key")
		}
		pub = &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
	default:
		return nil, 0, errors.New("unsupported key type")
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	return der, int(alg), err
}

// Registration is what the browser returns from navigator.credentials.create.
type Registration struct {
	ID                string `json:"id"`
	ClientDataJSON    string `json:"client_data"`
	AttestationObject string `json:"attestation"`
}

// VerifyRegistration checks a new credential and returns it. Only the
// "none" attestation format is accepted together with self-made ones
// ("packed" without a certificate); PassZit does not need to know the
// make of the key.
func VerifyRegistration(reg Registration, challenge []byte, rpID string, origins []string) (*Credential, error) {
	cd, err := B64.DecodeString(reg.ClientDataJSON)
	if err != nil {
		return nil, errors.New("unreadable client data")
	}
	if err := checkClientData(cd, "webauthn.create", challenge, origins); err != nil {
		return nil, err
	}
	ao, err := B64.DecodeString(reg.AttestationObject)
	if err != nil {
		return nil, errors.New("unreadable attestation")
	}
	v, _, err := decodeCBOR(ao)
	if err != nil {
		return nil, err
	}
	m, ok := v.(map[any]any)
	if !ok {
		return nil, errors.New("unreadable attestation")
	}
	raw, _ := m["authData"].([]byte)
	a, err := parseAuthData(raw, true)
	if err != nil {
		return nil, err
	}
	h := sha256.Sum256([]byte(rpID))
	if subtle.ConstantTimeCompare(a.rpIDHash, h[:]) != 1 {
		return nil, errors.New("the key belongs to another site")
	}
	if a.flags&flagUP == 0 {
		return nil, errors.New("the key was not touched")
	}
	id, err := B64.DecodeString(reg.ID)
	if err != nil || subtle.ConstantTimeCompare(id, a.credID) != 1 {
		return nil, errors.New("the credential id does not match")
	}
	pub, alg, err := parseCOSEKey(a.coseKey)
	if err != nil {
		return nil, err
	}
	return &Credential{ID: a.credID, PublicKey: pub, Alg: alg, SignCount: a.signCount}, nil
}

// Assertion is what the browser returns from navigator.credentials.get.
type Assertion struct {
	ID                string `json:"id"`
	ClientDataJSON    string `json:"client_data"`
	AuthenticatorData string `json:"authenticator_data"`
	Signature         string `json:"signature"`
}

// VerifyAssertion checks a sign-in with a registered credential and
// returns the new signature counter.
func VerifyAssertion(as Assertion, cred Credential, challenge []byte, rpID string, origins []string) (uint32, error) {
	cd, err1 := B64.DecodeString(as.ClientDataJSON)
	ad, err2 := B64.DecodeString(as.AuthenticatorData)
	sig, err3 := B64.DecodeString(as.Signature)
	if err1 != nil || err2 != nil || err3 != nil {
		return 0, errors.New("unreadable answer of the key")
	}
	if err := checkClientData(cd, "webauthn.get", challenge, origins); err != nil {
		return 0, err
	}
	a, err := parseAuthData(ad, false)
	if err != nil {
		return 0, err
	}
	h := sha256.Sum256([]byte(rpID))
	if subtle.ConstantTimeCompare(a.rpIDHash, h[:]) != 1 {
		return 0, errors.New("the key answered for another site")
	}
	if a.flags&flagUP == 0 {
		return 0, errors.New("the key was not touched")
	}
	ch := sha256.Sum256(cd)
	msg := append(append([]byte(nil), ad...), ch[:]...)
	k, err := x509.ParsePKIXPublicKey(cred.PublicKey)
	if err != nil {
		return 0, err
	}
	ok := false
	switch pk := k.(type) {
	case *ecdsa.PublicKey:
		d := sha256.Sum256(msg)
		ok = cred.Alg == AlgES256 && ecdsa.VerifyASN1(pk, d[:], sig)
	case ed25519.PublicKey:
		ok = cred.Alg == AlgEdDSA && ed25519.Verify(pk, msg, sig)
	case *rsa.PublicKey:
		d := sha256.Sum256(msg)
		ok = cred.Alg == AlgRS256 && rsa.VerifyPKCS1v15(pk, crypto.SHA256, d[:], sig) == nil
	}
	if !ok {
		return 0, errors.New("the signature of the key is wrong")
	}
	// A counter that does not grow points to a cloned key (counters of 0
	// mean the key does not count, as passkeys do).
	if a.signCount != 0 || cred.SignCount != 0 {
		if a.signCount <= cred.SignCount {
			return 0, errors.New("the signature counter of the key went back; the key may be cloned")
		}
	}
	return a.signCount, nil
}
