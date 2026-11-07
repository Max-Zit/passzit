package main

import (
	"encoding/json"
	"testing"
	"time"
)

// The command line reads authenticator keys and whole vault items that
// other clients wrote; rotation settings decide what it changes on devices.

func FuzzTOTPNow(f *testing.F) {
	f.Add("JBSWY3DPEHPK3PXP")
	f.Add("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&algorithm=SHA512&digits=8&period=60")
	f.Add("otpauth://totp/x?secret=&period=0&digits=99")
	f.Fuzz(func(t *testing.T, s string) {
		_, _ = totpNow(s, time.Now())
	})
}

func FuzzRawItem(f *testing.F) {
	f.Add([]byte(`{"type":"login","login":{"username":"root","password":"x"},"connect":{"tool":"ssh","host":"10.0.0.1","port":22},"rotation":{"method":"linux","days":30,"last":"2026-01-01T00:00:00Z"}}`))
	f.Add([]byte(`{"rotation":{"method":"x","days":-9223372036854775808}}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		var d map[string]any
		if json.Unmarshal(b, &d) != nil {
			return
		}
		it := rawItem{Data: d}
		_ = it.str("connect", "host")
		_ = it.str("connect", "port")
		if rt := it.rotation(); rt != nil && rt.Days <= 0 {
			t.Fatalf("rotation every %d days", rt.Days)
		}
		_ = it.due(time.Now())
	})
}
