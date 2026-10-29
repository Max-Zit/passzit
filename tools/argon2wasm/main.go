//go:build js && wasm

// argon2wasm is Argon2id for the browser clients: golang.org/x/crypto/argon2
// compiled to WebAssembly by tools/buildwasm. It exposes one function,
// pzArgon2id(password, salt, t, m, p) → Uint8Array(32), and is loaded only
// on the screens that derive a master key.
package main

import (
	"syscall/js"

	"golang.org/x/crypto/argon2"
)

func main() {
	js.Global().Set("pzArgon2id", js.FuncOf(func(_ js.Value, a []js.Value) any {
		if len(a) != 5 {
			return js.Null()
		}
		pw := make([]byte, a[0].Length())
		js.CopyBytesToGo(pw, a[0])
		salt := make([]byte, a[1].Length())
		js.CopyBytesToGo(salt, a[1])
		t, m, p := a[2].Int(), a[3].Int(), a[4].Int()
		if t < 1 || t > 20 || m < 8*1024 || m > 1024*1024 || p < 1 || p > 16 {
			return js.Null()
		}
		k := argon2.IDKey(pw, salt, uint32(t), uint32(m), uint8(p), 32)
		clear(pw)
		out := js.Global().Get("Uint8Array").New(len(k))
		js.CopyBytesToJS(out, k)
		clear(k)
		return out
	}))
	select {}
}
