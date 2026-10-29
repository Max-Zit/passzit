package qrscan

import (
	"image"
	"image/color"
	"image/draw"
	"testing"

	"rsc.io/qr"
)

// page puts QR codes on a bigger light page, like a screenshot of a
// website's two-factor setup.
func page(t *testing.T, scale int, texts ...string) image.Image {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, 1600, 900))
	draw.Draw(img, img.Bounds(), &image.Uniform{color.RGBA{0xf4, 0xf5, 0xf7, 0xff}}, image.Point{}, draw.Src)
	for i, s := range texts {
		c, err := qr.Encode(s, qr.M)
		if err != nil {
			t.Fatal(err)
		}
		c.Scale = scale
		q := c.Image()
		at := image.Pt(200+i*700, 150)
		draw.Draw(img, q.Bounds().Add(at), q, image.Point{}, draw.Src)
	}
	return img
}

func TestDecode(t *testing.T) {
	const a = "otpauth://totp/Example:ana@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example"
	const b = "otpauth://totp/Other:ana?secret=KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ&issuer=Other&digits=8"
	got, err := Decode(page(t, 4, a))
	if err != nil || len(got) != 1 || got[0] != a {
		t.Fatalf("one code: %q %v", got, err)
	}
	got, err = Decode(page(t, 3, a, b))
	if err != nil || len(got) != 2 {
		t.Fatalf("two codes: %q %v", got, err)
	}
	got, err = Decode(image.NewRGBA(image.Rect(0, 0, 300, 200)))
	if err != nil || len(got) != 0 {
		t.Fatalf("no code: %q %v", got, err)
	}
	if _, err := Decode(image.NewRGBA(image.Rect(0, 0, 0, 0))); err == nil {
		t.Fatal("empty image accepted")
	}
}
