// Package webauthn checks security keys and passkeys (W3C Web
// Authentication) as a second factor: registration without attestation
// ("none") and sign-in assertions with ES256, EdDSA or RS256.
package webauthn

import (
	"encoding/binary"
	"errors"
	"math"
)

// A small CBOR decoder (RFC 8949) for what WebAuthn uses: unsigned and
// negative integers, byte and text strings, arrays, maps, simple values.
// Indefinite lengths, floats and tags are refused; depth and sizes are
// limited.

var errCBOR = errors.New("malformed CBOR")

type cborDecoder struct {
	b     []byte
	depth int
}

func (d *cborDecoder) head() (major byte, arg uint64, err error) {
	if len(d.b) == 0 {
		return 0, 0, errCBOR
	}
	ib := d.b[0]
	d.b = d.b[1:]
	major, info := ib>>5, ib&0x1f
	switch {
	case info < 24:
		return major, uint64(info), nil
	case info == 24:
		if len(d.b) < 1 {
			return 0, 0, errCBOR
		}
		arg = uint64(d.b[0])
		d.b = d.b[1:]
	case info == 25:
		if len(d.b) < 2 {
			return 0, 0, errCBOR
		}
		arg = uint64(binary.BigEndian.Uint16(d.b))
		d.b = d.b[2:]
	case info == 26:
		if len(d.b) < 4 {
			return 0, 0, errCBOR
		}
		arg = uint64(binary.BigEndian.Uint32(d.b))
		d.b = d.b[4:]
	case info == 27:
		if len(d.b) < 8 {
			return 0, 0, errCBOR
		}
		arg = binary.BigEndian.Uint64(d.b)
		d.b = d.b[8:]
	default:
		return 0, 0, errCBOR // indefinite lengths and reserved values
	}
	return major, arg, nil
}

// value decodes one item: int64, []byte, string, []any, map[any]any, bool or nil.
func (d *cborDecoder) value() (any, error) {
	d.depth++
	defer func() { d.depth-- }()
	if d.depth > 16 {
		return nil, errCBOR
	}
	major, arg, err := d.head()
	if err != nil {
		return nil, err
	}
	switch major {
	case 0:
		if arg > math.MaxInt64 {
			return nil, errCBOR
		}
		return int64(arg), nil
	case 1:
		if arg > math.MaxInt64 {
			return nil, errCBOR
		}
		return -1 - int64(arg), nil
	case 2, 3:
		if arg > uint64(len(d.b)) {
			return nil, errCBOR
		}
		s := d.b[:arg]
		d.b = d.b[arg:]
		if major == 3 {
			return string(s), nil
		}
		return append([]byte(nil), s...), nil
	case 4:
		if arg > 256 {
			return nil, errCBOR
		}
		out := make([]any, 0, arg)
		for i := uint64(0); i < arg; i++ {
			v, err := d.value()
			if err != nil {
				return nil, err
			}
			out = append(out, v)
		}
		return out, nil
	case 5:
		if arg > 256 {
			return nil, errCBOR
		}
		out := make(map[any]any, arg)
		for i := uint64(0); i < arg; i++ {
			k, err := d.value()
			if err != nil {
				return nil, err
			}
			switch k.(type) {
			case int64, string:
			default:
				return nil, errCBOR
			}
			v, err := d.value()
			if err != nil {
				return nil, err
			}
			out[k] = v
		}
		return out, nil
	case 7:
		switch arg {
		case 20:
			return false, nil
		case 21:
			return true, nil
		case 22, 23:
			return nil, nil
		}
	}
	return nil, errCBOR
}

// decodeCBOR decodes one item and returns the bytes after it.
func decodeCBOR(b []byte) (any, []byte, error) {
	d := &cborDecoder{b: b}
	v, err := d.value()
	return v, d.b, err
}
