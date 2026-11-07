package connect

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"testing"
)

// The launcher reads native messages from the browser extension: frames and
// connection requests must be refused cleanly when they are malformed.

func FuzzReadMessage(f *testing.F) {
	msg := []byte(`{"v":1,"tool":"ssh","host":"10.0.0.5","user":"root"}`)
	frame := binary.LittleEndian.AppendUint32(nil, uint32(len(msg))) // #nosec G115 -- a short constant
	f.Add(append(frame, msg...))
	f.Add([]byte{0xff, 0xff, 0xff, 0x7f})
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = ReadMessage(bytes.NewReader(b))
	})
}

func FuzzPlan(f *testing.F) {
	for _, s := range []string{
		`{"v":1,"tool":"rdp","host":"srv.example.com","user":"admin","password":"x"}`,
		`{"v":1,"tool":"ssh","host":"[fe80::1]","port":2222,"user":"root","key":"-----BEGIN OPENSSH PRIVATE KEY-----"}`,
		`{"v":1,"tool":"winbox","host":"192.168.88.1","user":"admin","password":"p w"}`,
		`{"v":1,"tool":"vnc","host":"-oProxyCommand=x"}`,
	} {
		f.Add([]byte(s), "linux")
		f.Add([]byte(s), "windows")
	}
	f.Fuzz(func(t *testing.T, raw []byte, goos string) {
		var r Request
		if json.Unmarshal(raw, &r) != nil {
			return
		}
		env := Env{GOOS: goos, LookPath: func(names ...string) (string, error) { return "/usr/bin/" + names[0], nil }}
		a, err := Plan(r, env)
		if err != nil || a == nil {
			return
		}
		// what passed is safe to hand to a program: a valid host, no
		// option smuggled in as the host
		if !ValidHost(r.Host) {
			t.Fatalf("planned a connection to the invalid host %q", r.Host)
		}
		for _, arg := range a.Args {
			if arg == r.Host && len(arg) > 0 && arg[0] == '-' {
				t.Fatalf("host %q passed as an option", arg)
			}
		}
	})
}
