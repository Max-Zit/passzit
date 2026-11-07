package auth

import (
	"testing"
	"time"
)

// Authenticator secrets come from settings and imports; codes are typed by
// people at sign-in.

func FuzzTOTP(f *testing.F) {
	f.Add(NewTOTPSecret(), "123456", int64(0))
	f.Add("not base32!", "", int64(-1))
	f.Fuzz(func(t *testing.T, secret, code string, last int64) {
		_, _ = TOTPCode(secret, time.Now().Unix()/30)
		_, _ = TOTPVerify(secret, code, time.Now(), last)
	})
}
