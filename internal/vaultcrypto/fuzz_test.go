package vaultcrypto

import "testing"

// Sealed values come from the server (or a file) and must never open with
// the wrong key or data, nor panic when damaged.

func FuzzOpen(f *testing.F) {
	key := Random(32)
	good, _ := Seal(key, []byte("secret"), "aad")
	f.Add(good, "aad")
	f.Add("", "")
	f.Add("AQ", "aad")
	f.Fuzz(func(t *testing.T, sealed, aad string) {
		plain, err := Open(key, sealed, aad)
		if err == nil && sealed != good {
			// a different text may only open to the same bytes (base64 variants)
			if string(plain) != "secret" {
				t.Fatalf("a forged value opened: %q", plain)
			}
		}
	})
}

func FuzzOpenSealed(f *testing.F) {
	pub, priv, err := NewKeyPair()
	if err != nil {
		f.Fatal(err)
	}
	good, _ := SealTo(pub, []byte("vault key"), "v")
	f.Add(good, "v")
	f.Add("AQAA", "v")
	f.Fuzz(func(t *testing.T, sealed, aad string) {
		_, _ = OpenSealed(priv, sealed, aad)
	})
}

func FuzzParseRecoveryKey(f *testing.F) {
	f.Add(NewRecoveryKey())
	f.Add("ABCD-EFGH")
	f.Fuzz(func(t *testing.T, s string) {
		raw, err := ParseRecoveryKey(s)
		if err != nil {
			return
		}
		if again, err := ParseRecoveryKey(FormatRecoveryKey(raw)); err != nil || string(again) != string(raw) {
			t.Fatalf("recovery key %q does not round-trip", s)
		}
	})
}
