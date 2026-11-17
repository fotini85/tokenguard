package authmw

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/fotini85/tokenguard/internal/bloom"
	"github.com/fotini85/tokenguard/internal/bucket"
	"github.com/fotini85/tokenguard/internal/limiter"
	"github.com/fotini85/tokenguard/internal/token"
)

// Inside the package rather than authmw_test, because clientAddr is
// unexported and is the function worth testing: it decides which address
// a caller is rate limited under, from a header the caller can write.
//
// Addresses come from the documentation ranges, so nothing here could be
// mistaken for a real host:
//
//	192.0.2.0/24     the client
//	198.51.100.0/24  proxies we control
//	203.0.113.0/24   whatever the caller put in the header themselves
func request(remoteAddr, xff string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = remoteAddr
	if xff != "" {
		r.Header.Set("X-Forwarded-For", xff)
	}
	return r
}

func TestClientAddr(t *testing.T) {
	tests := []struct {
		name       string
		remoteAddr string
		xff        string
		hops       int
		want       string
	}{
		{
			// Nothing in front of us, so the header is simply input from
			// a stranger. Honouring it would hand out a fresh identity
			// per request and the rate limiter would never fire.
			name:       "no proxy configured, header ignored",
			remoteAddr: "198.51.100.7:4000",
			xff:        "203.0.113.9",
			hops:       0,
			want:       "198.51.100.7",
		},
		{
			name:       "proxy configured but no header",
			remoteAddr: "198.51.100.7:4000",
			hops:       1,
			want:       "198.51.100.7",
		},
		{
			name:       "one proxy, one entry",
			remoteAddr: "198.51.100.7:4000",
			xff:        "192.0.2.5",
			hops:       1,
			want:       "192.0.2.5",
		},
		{
			// The whole reason for counting from the right. Our proxy
			// appended the address it actually saw, so the caller's own
			// entry sits to the left of it and is skipped.
			name:       "one proxy, caller prepended a forgery",
			remoteAddr: "198.51.100.7:4000",
			xff:        "203.0.113.9, 192.0.2.5",
			hops:       1,
			want:       "192.0.2.5",
		},
		{
			name:       "two proxies",
			remoteAddr: "198.51.100.7:4000",
			xff:        "192.0.2.5, 198.51.100.1",
			hops:       2,
			want:       "192.0.2.5",
		},
		{
			name:       "two proxies, caller prepended a forgery",
			remoteAddr: "198.51.100.7:4000",
			xff:        "203.0.113.9, 192.0.2.5, 198.51.100.1",
			hops:       2,
			want:       "192.0.2.5",
		},
		{
			// Fewer entries than proxies means the chain is not what we
			// were told it is. Reading further left than the header goes
			// is not an option, so fall back to the connection.
			name:       "fewer entries than configured hops",
			remoteAddr: "198.51.100.7:4000",
			xff:        "192.0.2.5",
			hops:       3,
			want:       "198.51.100.7",
		},
		{
			name:       "unparseable entry",
			remoteAddr: "198.51.100.7:4000",
			xff:        "not-an-address",
			hops:       1,
			want:       "198.51.100.7",
		},
		{
			name:       "surrounding whitespace is trimmed",
			remoteAddr: "198.51.100.7:4000",
			xff:        "203.0.113.9 ,   192.0.2.5  ",
			hops:       1,
			want:       "192.0.2.5",
		},
		{
			name:       "ipv6 entry",
			remoteAddr: "[2001:db8::7]:4000",
			xff:        "2001:db8:1::5",
			hops:       1,
			want:       "2001:db8:1::5",
		},
		{
			// Left mapped on purpose. Unwrapping is KeyForAddr's job, and
			// doing it in both places would mean two things to keep in
			// step for no gain.
			name:       "ipv4-mapped entry is returned as-is",
			remoteAddr: "198.51.100.7:4000",
			xff:        "::ffff:192.0.2.5",
			hops:       1,
			want:       "::ffff:192.0.2.5",
		},
		{
			name:       "remote address without a port",
			remoteAddr: "198.51.100.7",
			hops:       0,
			want:       "198.51.100.7",
		},
		{
			// A port here is legal in RFC 7239 but ParseAddr will not
			// take it, so the entry is discarded. Documented rather than
			// handled: the direction of the failure is the safe one.
			name:       "entry carrying a port is discarded",
			remoteAddr: "198.51.100.7:4000",
			xff:        "192.0.2.5:1234",
			hops:       1,
			want:       "198.51.100.7",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := clientAddr(request(tt.remoteAddr, tt.xff), tt.hops)
			if err != nil {
				t.Fatalf("clientAddr() error = %v", err)
			}
			if got.String() != tt.want {
				t.Errorf("clientAddr() = %v, want %v", got, tt.want)
			}
		})
	}
}

// Sixteen entries are allowed; seventeen must be refused outright rather
// than truncated to sixteen.
//
// trustedHops is set to the cap so the two behaviours are visibly
// different. Splitting *at* the cap leaves sixteen elements with the
// rest crammed into the last one, so index len-16 becomes index 0 — and
// index 0 is the first thing the caller wrote. Splitting one *past* the
// cap leaves seventeen, the check fires, and the connection's own
// address is used instead.
func TestClientAddrRefusesTooManyEntries(t *testing.T) {
	const hops = maxXFEntries

	// Every entry is in the caller's range, so any answer taken from the
	// header at all is a failure.
	entries := make([]string, maxXFEntries+4)
	for i := range entries {
		entries[i] = fmt.Sprintf("203.0.113.%d", i+1)
	}

	got, err := clientAddr(request("198.51.100.7:4000", strings.Join(entries, ", ")), hops)
	if err != nil {
		t.Fatalf("clientAddr() error = %v", err)
	}

	if got.String() == entries[0] {
		t.Fatalf("clientAddr() = %v, the caller's first entry: the slice was "+
			"truncated, so counting from the right landed inside their data", got)
	}
	if got.String() != "198.51.100.7" {
		t.Errorf("clientAddr() = %v, want 198.51.100.7 (the connection itself)", got)
	}
}

// The boundary on the other side: exactly the cap is still honoured, or
// the fix above would have turned into an off-by-one that ignores the
// header for anyone behind a long but legitimate chain.
func TestClientAddrAcceptsExactlyTheCap(t *testing.T) {
	entries := make([]string, maxXFEntries)
	for i := range entries {
		entries[i] = fmt.Sprintf("203.0.113.%d", i+1)
	}
	entries[len(entries)-1] = "192.0.2.5" // what our proxy appended

	got, err := clientAddr(request("198.51.100.7:4000", strings.Join(entries, ", ")), 1)
	if err != nil {
		t.Fatalf("clientAddr() error = %v", err)
	}
	if got.String() != "192.0.2.5" {
		t.Errorf("clientAddr() = %v, want 192.0.2.5", got)
	}
}

func TestClientAddrErrorsOnUnparseableRemoteAddr(t *testing.T) {
	if _, err := clientAddr(request("not-an-address", ""), 0); err == nil {
		t.Error("clientAddr() succeeded on an unparseable RemoteAddr")
	}
}

type fakeRevocations struct{}

func (fakeRevocations) IsRevoked(context.Context, string) (bool, error) { return false, nil }

func validConfig() Config {
	policy := bucket.Policy{AllowedRequests: 1, Window: time.Second}
	return Config{
		Codec:     token.NewCodec(make([]byte, 32), nil),
		IPLimit:   limiter.New(limiter.Config{Policy: policy, MaxKeys: 1}),
		UserLimit: limiter.New(limiter.Config{Policy: policy, MaxKeys: 1}),
	}
}

// Revocation checking has two halves and both have to be present. Each
// way of wiring only one fails somewhere other than startup: a denylist
// with no store panics on the first bloom hit, which is the first time
// anyone revokes anything; a store with no denylist is never consulted,
// so revoked sessions keep working and nothing looks wrong.
func TestNewRequiresRevocationWiredWholeOrNotAtAll(t *testing.T) {
	denylist := func() *bloom.Rotating {
		return bloom.NewRotating(8, 0.01, time.Minute, time.Now())
	}

	tests := []struct {
		name   string
		adjust func(*Config)
		panics bool
	}{
		{"neither", func(*Config) {}, false},
		{"both", func(c *Config) {
			c.Denylist = denylist()
			c.Revoked = fakeRevocations{}
		}, false},
		{"denylist without store", func(c *Config) {
			c.Denylist = denylist()
		}, true},
		{"store without denylist", func(c *Config) {
			c.Revoked = fakeRevocations{}
		}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validConfig()
			tt.adjust(&cfg)

			defer func() {
				switch v := recover(); {
				case v == nil && tt.panics:
					t.Error("New() did not panic")
				case v != nil && !tt.panics:
					t.Errorf("New() panicked: %v", v)
				}
			}()
			New(cfg)
		})
	}
}
