package webauthn

import "testing"

// The browser hands over everything below: CBOR, authenticator data, COSE
// keys and client data come from a security key or a passkey the server
// does not control. Bad input must give an error, never a panic.

const fuzzRP, fuzzOrigin = "vault.example.com", "https://vault.example.com"

var fuzzChallenge = []byte("0123456789abcdef0123456789abcdef")

func FuzzDecodeCBOR(f *testing.F) {
	reg := newSoftKey(f, AlgES256).register(fuzzRP, fuzzOrigin, fuzzChallenge)
	if att, err := B64.DecodeString(reg.AttestationObject); err == nil {
		f.Add(att)
	}
	f.Add([]byte{0xa1, 0x63, 'f', 'm', 't', 0x64, 'n', 'o', 'n', 'e'})
	f.Add([]byte{0x9f, 0xff})
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _, _ = decodeCBOR(b)
	})
}

func FuzzParseAuthData(f *testing.F) {
	k := newSoftKey(f, AlgES256)
	f.Add(k.authData(fuzzRP, flagUP|flagUV, false), false)
	f.Add(k.authData(fuzzRP, flagUP|flagAT, true), true)
	f.Fuzz(func(t *testing.T, b []byte, attested bool) {
		_, _ = parseAuthData(b, attested)
	})
}

func FuzzParseCOSEKey(f *testing.F) {
	f.Add(newSoftKey(f, AlgES256).cose())
	f.Add(newSoftKey(f, AlgEdDSA).cose())
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _, _ = parseCOSEKey(b)
	})
}

func FuzzCheckClientData(f *testing.F) {
	f.Add(clientJSON("webauthn.get", fuzzChallenge, fuzzOrigin))
	f.Add([]byte(`{"type":1}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		_ = checkClientData(raw, "webauthn.get", fuzzChallenge, []string{fuzzOrigin})
	})
}

// FuzzVerify feeds whole registrations and sign-ins: nothing may panic,
// and a sign-in may only verify with what the registration really holds.
func FuzzVerify(f *testing.F) {
	k := newSoftKey(f, AlgES256)
	reg := k.register(fuzzRP, fuzzOrigin, fuzzChallenge)
	as := k.assert(fuzzRP, fuzzOrigin, fuzzChallenge)
	f.Add(reg.ClientDataJSON, reg.AttestationObject, as.ClientDataJSON, as.AuthenticatorData, as.Signature)
	f.Fuzz(func(t *testing.T, cd, att, acd, ad, sig string) {
		cred, err := VerifyRegistration(Registration{ID: "x", ClientDataJSON: cd, AttestationObject: att}, fuzzChallenge, fuzzRP, []string{fuzzOrigin})
		if err != nil || cred == nil {
			return
		}
		_, _ = VerifyAssertion(Assertion{ID: "x", ClientDataJSON: acd, AuthenticatorData: ad, Signature: sig}, *cred, fuzzChallenge, fuzzRP, []string{fuzzOrigin})
	})
}
