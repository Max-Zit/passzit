package netacl

import (
	"net/netip"
	"testing"
)

// Allowed networks are typed by administrators and read back from settings.

func FuzzParse(f *testing.F) {
	f.Add("192.168.1.0/24, 10.0.0.1 fd00::/8")
	f.Add("::ffff:1.2.3.4/128")
	f.Fuzz(func(t *testing.T, s string) {
		ps, err := Parse(Split(s))
		if err != nil {
			return
		}
		again, err := Parse(Strings(ps))
		if err != nil || len(again) != len(ps) {
			t.Fatalf("%q does not round-trip: %v", s, err)
		}
		_ = Contains(ps, netip.MustParseAddr("10.0.0.1"))
		_, _ = AddrOf(s)
	})
}
