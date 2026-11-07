package store

import (
	"bytes"
	"testing"
)

// Input checks of the store: sealed blobs and ids of vault and sharing
// requests (the server stores what it cannot read, so the shape is all it
// checks), e-mail addresses, and the frames of a restored backup.

func FuzzSealedChecks(f *testing.F) {
	f.Add("AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", 100)
	f.Add("", 0)
	f.Fuzz(func(t *testing.T, s string, max int) {
		_ = SealedOK(s, max)
		_ = SealedToOK(s, max)
		_ = ValidID(s)
		_ = ValidRights(s)
	})
}

func FuzzNormEmail(f *testing.F) {
	f.Add("Ana@Example.com")
	f.Add("a@b")
	f.Add(" x@\x00y.com")
	f.Fuzz(func(t *testing.T, s string) {
		e, err := NormEmail(s)
		if err != nil {
			return
		}
		if again, err := NormEmail(e); err != nil || again != e {
			t.Fatalf("NormEmail(%q) = %q, not stable", s, e)
		}
	})
}

func FuzzReadFrame(f *testing.F) {
	var b bytes.Buffer
	_ = writeFrame(&b, 'd', []byte("COPY data"))
	f.Add(b.Bytes())
	f.Add([]byte{'d', 0xff, 0xff, 0xff, 0xff})
	f.Fuzz(func(t *testing.T, in []byte) {
		r := bytes.NewReader(in)
		for i := 0; i < 16; i++ {
			if _, _, err := readFrame(r); err != nil {
				return
			}
		}
	})
}
