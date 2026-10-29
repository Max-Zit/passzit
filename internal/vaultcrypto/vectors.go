package vaultcrypto

// Vectors fixes the outputs of every derivation, so the JavaScript client
// (static/pz/crypto.js, tested in a browser by internal/web) and this
// package stay byte-compatible. Change them only together with a scheme
// version change.
var Vectors = struct {
	Password, SaltHex        string
	KDF                      KDF
	MasterHex, AuthHex, Wrap string
	PBKDF2Master             string
	KeyHex, NonceHex, AAD    string
	Plain, Sealed            string
}{
	Password:     "Correct horse battery staple ✓",
	SaltHex:      "000102030405060708090a0b0c0d0e0f",
	KDF:          KDF{Alg: "argon2id", M: 19 * 1024, T: 2, P: 1},
	MasterHex:    "1380ec467a20ca2e390d975e688257064ae339fae8628c2c1bde54fac28ea9a9",
	AuthHex:      "d0693783beed3a9f259aef81f02a650dd672a4a35442f6565785ce815dd01179",
	Wrap:         "61e65448ab643a2f94505084dca46effec2fcb22a674a11ec67893cede7cd606",
	PBKDF2Master: "4fb3e9dde3ab12c48c50f6263ba1fadff13b91804d2e59301e4e70bfad07bfc5",
	KeyHex:       "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
	NonceHex:     "a0a1a2a3a4a5a6a7a8a9aaab",
	AAD:          "passzit/item/v1|vault|item",
	Plain:        `{"name":"Example"}`,
	Sealed:       "AaChoqOkpaanqKmqq506EkworiCFQCD_smoKrLtS0W414ORI4qcGvf1fj8XnzsU",
}
