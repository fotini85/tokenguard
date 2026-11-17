package limiter_test

import (
	"net/netip"
	"testing"

	"github.com/fotini85/tokenguard/internal/limiter"
)

func TestKeyForAddr(t *testing.T) {
	tests := []struct {
		name string
		addr string
		want string
	}{
		{
			// One subscriber, one address. Nothing to truncate.
			name: "ipv4 is used whole",
			addr: "192.0.2.5",
			want: "192.0.2.5",
		},
		{
			// The same client reaching a dual-stack listener can arrive
			// wrapped. Without unwrapping it would be truncated as if it
			// were v6, and one caller would hold two keys depending on
			// how the connection happened to be made.
			name: "ipv4-mapped unwraps to the plain form",
			addr: "::ffff:192.0.2.5",
			want: "192.0.2.5",
		},
		{
			name: "ipv6 is cut to its /64",
			addr: "2001:db8:1:2:3:4:5:6",
			want: "2001:db8:1:2::/64",
		},
		{
			name: "an address already on a /64 boundary is unchanged",
			addr: "2001:db8:1:2::",
			want: "2001:db8:1:2::/64",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := limiter.KeyForAddr(netip.MustParseAddr(tt.addr))
			if got != tt.want {
				t.Errorf("KeyForAddr(%s) = %q, want %q", tt.addr, got, tt.want)
			}
		})
	}
}

// The whole reason for truncating. A subscriber is handed a /64 — 18
// quintillion addresses — and every one of them has to count as the
// same caller, or they never reach a limit and every request adds a map
// entry until memory runs out.
func TestKeyForAddrGroupsASubscribersWholeBlock(t *testing.T) {
	block := []string{
		"2001:db8:1:2::1",
		"2001:db8:1:2::dead:beef",
		"2001:db8:1:2:ffff:ffff:ffff:ffff",
	}

	first := limiter.KeyForAddr(netip.MustParseAddr(block[0]))
	for _, a := range block[1:] {
		if got := limiter.KeyForAddr(netip.MustParseAddr(a)); got != first {
			t.Errorf("%s keyed as %q, want %q: same subscriber, different buckets", a, got, first)
		}
	}
}

// And the other direction. Cutting wider — at /48, say — would put
// unrelated subscribers of one provider in a single bucket, where any
// of them could lock out the rest.
func TestKeyForAddrSeparatesNeighbouringBlocks(t *testing.T) {
	a := limiter.KeyForAddr(netip.MustParseAddr("2001:db8:1:2::1"))
	b := limiter.KeyForAddr(netip.MustParseAddr("2001:db8:1:3::1"))

	if a == b {
		t.Errorf("two different /64s share the key %q", a)
	}
}
