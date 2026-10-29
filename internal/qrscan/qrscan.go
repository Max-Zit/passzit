// Package qrscan reads QR codes from an image, for authenticator keys that
// websites show only as a QR code. It runs in the browser (tools/qrwasm), so
// the key never leaves the user's computer.
package qrscan

import (
	"errors"
	"image"

	"github.com/makiuchi-d/gozxing"
	multiqr "github.com/makiuchi-d/gozxing/multi/qrcode"
	"github.com/makiuchi-d/gozxing/qrcode"
)

// MaxPixels limits the image size (a 4K screen is about 8.3 million).
const MaxPixels = 40_000_000

// Decode returns the texts of all QR codes in img (none: an empty list).
func Decode(img image.Image) ([]string, error) {
	b := img.Bounds()
	if b.Dx() <= 0 || b.Dy() <= 0 || b.Dx()*b.Dy() > MaxPixels {
		return nil, errors.New("unsupported image size")
	}
	hints := map[gozxing.DecodeHintType]interface{}{gozxing.DecodeHintType_TRY_HARDER: true}
	var out []string
	seen := map[string]bool{}
	add := func(s string) {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	// The hybrid binarizer copes with photos; the global one with large,
	// clean codes on a screen. Several codes: the multi reader.
	for _, bin := range []func(gozxing.LuminanceSource) gozxing.Binarizer{gozxing.NewHybridBinarizer, gozxing.NewGlobalHistgramBinarizer} {
		bmp, err := gozxing.NewBinaryBitmap(bin(gozxing.NewLuminanceSourceFromImage(img)))
		if err != nil {
			continue
		}
		if rs, err := multiqr.NewQRCodeMultiReader().DecodeMultiple(bmp, hints); err == nil {
			for _, r := range rs {
				add(r.GetText())
			}
		}
		if len(out) == 0 {
			if r, err := qrcode.NewQRCodeReader().Decode(bmp, hints); err == nil {
				add(r.GetText())
			}
		}
		if len(out) > 0 {
			break
		}
	}
	return out, nil
}
