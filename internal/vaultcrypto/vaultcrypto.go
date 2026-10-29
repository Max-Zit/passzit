// Package vaultcrypto is the client-side cryptography of PassZit written in
// Go. The browser clients (web vault, extension) implement the same scheme
// in JavaScript (static/pz/crypto.js) with WebCrypto; this package is the
// reference both are tested against, and the server's tests use it to act as
// a real client. The server itself never calls the decrypting functions: it
// only ever stores what clients send.
//
// Scheme (version 1):
//
//	master key   = Argon2id(NFC(password), salt, t, m, p) → 32 bytes
//	auth key     = HKDF-SHA256(master key, info "passzit/auth/v1")  → sent to the server
//	wrap key     = HKDF-SHA256(master key, info "passzit/wrap/v1")  → wraps the account key
//	account key  = 32 random bytes (AES-256-GCM)
//	vault key    = 32 random bytes per vault, wrapped by the account key
//	item         = AES-256-GCM(vault key, JSON, AAD "passzit/item/v1|vault|item")
//
// A sealed value is base64url(0x01 ‖ 12-byte nonce ‖ ciphertext ‖ tag).
package vaultcrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base32"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/text/unicode/norm"
)

// Version is the first byte of every sealed value.
const Version = 1

// KDF names the key derivation of a master password.
type KDF struct {
	Alg string `json:"alg"` // "argon2id" or "pbkdf2-sha256"
	// Argon2id: memory in KiB, iterations, parallelism.
	M int `json:"m,omitempty"`
	T int `json:"t"`
	P int `json:"p,omitempty"`
}

// DefaultKDF is used for new accounts (64 MiB, 3 passes, 4 lanes).
var DefaultKDF = KDF{Alg: "argon2id", M: 64 * 1024, T: 3, P: 4}

// Validate refuses parameters that are too weak or too expensive for a browser.
func (k KDF) Validate() error {
	switch k.Alg {
	case "argon2id":
		if k.M < 19*1024 || k.M > 1024*1024 || k.T < 2 || k.T > 20 || k.P < 1 || k.P > 16 {
			return errors.New("argon2id parameters out of range (memory 19 MiB–1 GiB, 2–20 passes, 1–16 lanes)")
		}
	case "pbkdf2-sha256":
		if k.T < 600_000 || k.T > 10_000_000 {
			return errors.New("PBKDF2 needs 600 000–10 000 000 iterations")
		}
	default:
		return errors.New("unknown key derivation")
	}
	return nil
}

// Stronger reports whether k costs more than o (a reason to upgrade).
func (k KDF) Stronger(o KDF) bool {
	if k.Alg != o.Alg {
		return k.Alg == "argon2id"
	}
	return k.M*k.T > o.M*o.T || k.T > o.T && k.M >= o.M
}

// MasterKey derives the master key from a password.
func MasterKey(password string, salt []byte, k KDF) ([]byte, error) {
	if err := k.Validate(); err != nil {
		return nil, err
	}
	pw := []byte(norm.NFC.String(password))
	switch k.Alg {
	case "argon2id":
		return argon2.IDKey(pw, salt, uint32(k.T), uint32(k.M), uint8(k.P), 32), nil // #nosec G115 -- validated ranges
	default:
		return pbkdf2SHA256(pw, salt, k.T), nil
	}
}

// pbkdf2SHA256 is PBKDF2 with HMAC-SHA256, 32 bytes.
func pbkdf2SHA256(pw, salt []byte, iter int) []byte {
	k, err := pbkdf2.Key(sha256.New, string(pw), salt, iter, 32)
	if err != nil {
		panic(err)
	}
	return k
}

// Derive is HKDF-SHA256 without salt, 32 bytes.
func Derive(key []byte, info string) []byte {
	out, err := hkdf.Key(sha256.New, key, nil, info, 32)
	if err != nil {
		panic(err) // only for impossible lengths
	}
	return out
}

// Info strings of the derived keys.
const (
	InfoAuth         = "passzit/auth/v1"
	InfoWrap         = "passzit/wrap/v1"
	InfoRecoveryAuth = "passzit/recovery-auth/v1"
	InfoRecoveryWrap = "passzit/recovery-wrap/v1"
	InfoSeal         = "passzit/seal/v1"
)

// AAD builders: every ciphertext is bound to what it is and where it belongs.
func AADAccountKey() string             { return "passzit/account-key/v1" }
func AADPrivateKey() string             { return "passzit/private-key/v1" }
func AADVaultKey(vaultID string) string { return "passzit/vault-key/v1|" + vaultID }
func AADItem(vaultID, itemID string) string {
	return "passzit/item/v1|" + vaultID + "|" + itemID
}
func AADFolder(folderID string) string { return "passzit/folder/v1|" + folderID }
func AADSession() string               { return "passzit/session/v1" }
func AADExport() string                { return "passzit/export/v1" }

// Random returns n random bytes.
func Random(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

// B64 is the encoding of keys and sealed values (base64url, no padding).
var B64 = base64.RawURLEncoding

// Seal encrypts plain under key (32 bytes) with a random nonce.
func Seal(key, plain []byte, aad string) (string, error) {
	return sealNonce(key, plain, aad, Random(12))
}

func sealNonce(key, plain []byte, aad string, nonce []byte) (string, error) {
	g, err := gcm(key)
	if err != nil {
		return "", err
	}
	out := append([]byte{Version}, nonce...)
	out = g.Seal(out, nonce, plain, []byte(aad))
	return B64.EncodeToString(out), nil
}

// ErrDecrypt hides why decryption failed (wrong key, tampering, wrong place).
var ErrDecrypt = errors.New("cannot decrypt (wrong key or damaged data)")

// Open decrypts a sealed value.
func Open(key []byte, sealed, aad string) ([]byte, error) {
	raw, err := B64.DecodeString(sealed)
	if err != nil || len(raw) < 1+12+16 || raw[0] != Version {
		return nil, ErrDecrypt
	}
	g, err := gcm(key)
	if err != nil {
		return nil, err
	}
	out, err := g.Open(nil, raw[1:13], raw[13:], []byte(aad))
	if err != nil {
		return nil, ErrDecrypt
	}
	return out, nil
}

func gcm(key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, errors.New("keys are 32 bytes")
	}
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(b)
}

// ---- key pairs (sharing)

// NewKeyPair creates an X25519 key pair: the public key as raw bytes and
// the private key as PKCS #8 (the form WebCrypto exports).
func NewKeyPair() (pub, privPKCS8 []byte, err error) {
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return nil, nil, err
	}
	return k.PublicKey().Bytes(), der, nil
}

// SealTo encrypts a key for the owner of an X25519 public key: an ephemeral
// key pair, ECDH, HKDF (salt = ephemeral ‖ recipient public key), AES-GCM.
// The result is base64url(ephemeral public key ‖ sealed bytes).
func SealTo(recipientPub, plain []byte, aad string) (string, error) {
	pub, err := ecdh.X25519().NewPublicKey(recipientPub)
	if err != nil {
		return "", err
	}
	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	shared, err := eph.ECDH(pub)
	if err != nil {
		return "", err
	}
	k, err := hkdf.Key(sha256.New, shared, append(eph.PublicKey().Bytes(), recipientPub...), InfoSeal, 32)
	if err != nil {
		return "", err
	}
	inner, err := Seal(k, plain, aad)
	if err != nil {
		return "", err
	}
	raw, _ := B64.DecodeString(inner)
	return B64.EncodeToString(append(eph.PublicKey().Bytes(), raw...)), nil
}

// OpenSealed reverses SealTo with the recipient's PKCS #8 private key.
func OpenSealed(privPKCS8 []byte, sealed, aad string) ([]byte, error) {
	raw, err := B64.DecodeString(sealed)
	if err != nil || len(raw) < 32+1+12+16 {
		return nil, ErrDecrypt
	}
	k, err := x509.ParsePKCS8PrivateKey(privPKCS8)
	if err != nil {
		return nil, err
	}
	priv, ok := k.(*ecdh.PrivateKey)
	if !ok || priv.Curve() != ecdh.X25519() {
		return nil, errors.New("not an X25519 key")
	}
	ephPub, err := ecdh.X25519().NewPublicKey(raw[:32])
	if err != nil {
		return nil, ErrDecrypt
	}
	shared, err := priv.ECDH(ephPub)
	if err != nil {
		return nil, ErrDecrypt
	}
	key, err := hkdf.Key(sha256.New, shared, append(raw[:32:32], priv.PublicKey().Bytes()...), InfoSeal, 32)
	if err != nil {
		return nil, err
	}
	return Open(key, B64.EncodeToString(raw[32:]), aad)
}

// Fingerprint is a short, comparable form of a public key (for people
// checking each other's keys): SHA-256, first 20 bytes, groups of four hex digits.
func Fingerprint(pub []byte) string {
	h := sha256.Sum256(pub)
	s := fmt.Sprintf("%x", h[:20])
	var b strings.Builder
	for i := 0; i < len(s); i += 4 {
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(s[i : i+4])
	}
	return b.String()
}

// ---- recovery key

var recoveryEnc = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewRecoveryKey returns 160 random bits as 32 base32 characters in groups of four.
func NewRecoveryKey() string { return FormatRecoveryKey(Random(20)) }

// FormatRecoveryKey writes raw recovery-key bytes for people.
func FormatRecoveryKey(raw []byte) string {
	s := recoveryEnc.EncodeToString(raw)
	var b strings.Builder
	for i := 0; i < len(s); i += 4 {
		if i > 0 {
			b.WriteByte('-')
		}
		b.WriteString(s[i:min(i+4, len(s))])
	}
	return b.String()
}

// ParseRecoveryKey accepts the key with or without dashes and spaces, any case.
func ParseRecoveryKey(s string) ([]byte, error) {
	s = strings.ToUpper(strings.NewReplacer("-", "", " ", "").Replace(strings.TrimSpace(s)))
	s = strings.NewReplacer("0", "O", "1", "I", "8", "B").Replace(s) // common misreadings
	raw, err := recoveryEnc.DecodeString(s)
	if err != nil || len(raw) != 20 {
		return nil, errors.New("this is not a recovery key")
	}
	return raw, nil
}
