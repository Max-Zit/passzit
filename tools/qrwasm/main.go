//go:build js && wasm

// qrwasm reads QR codes in the browser clients (internal/qrscan compiled to
// WebAssembly by tools/buildwasm). It exposes one function,
// pzReadQR(rgba Uint8Array|Uint8ClampedArray, width, height) → [text, …],
// and is loaded only when someone reads an authenticator QR code.
package main

import (
	"image"
	"syscall/js"

	"github.com/max-zit/passzit/internal/qrscan"
)

func main() {
	js.Global().Set("pzReadQR", js.FuncOf(func(_ js.Value, a []js.Value) any {
		if len(a) != 3 {
			return js.Null()
		}
		w, h := a[1].Int(), a[2].Int()
		if w <= 0 || h <= 0 || w*h > qrscan.MaxPixels || a[0].Length() != w*h*4 {
			return js.Null()
		}
		img := &image.NRGBA{Pix: make([]byte, w*h*4), Stride: w * 4, Rect: image.Rect(0, 0, w, h)}
		js.CopyBytesToGo(img.Pix, a[0])
		texts, err := qrscan.Decode(img)
		if err != nil {
			return js.Null()
		}
		out := js.Global().Get("Array").New()
		for _, s := range texts {
			out.Call("push", s)
		}
		return out
	}))
	select {}
}
