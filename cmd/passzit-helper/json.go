package main

import (
	"bytes"
	"encoding/json"
)

// jsonUnmarshal refuses unknown fields (a message is exactly a request).
func jsonUnmarshal(b []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	return d.Decode(v)
}
