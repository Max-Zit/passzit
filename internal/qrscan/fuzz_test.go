package qrscan

import (
	"bytes"
	"image"
	_ "image/png"
	"testing"
)

// QR codes are read from pictures people choose or paste (screenshots of
// two-factor setups); a damaged or crafted picture must not crash.

func FuzzDecode(f *testing.F) {
	f.Add([]byte("\x89PNG\r\n\x1a\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		img, _, err := image.Decode(bytes.NewReader(b))
		if err != nil {
			return
		}
		if r := img.Bounds(); r.Dx()*r.Dy() > 4<<20 {
			return // the browser limits picture size before this
		}
		_, _ = Decode(img)
	})
}
