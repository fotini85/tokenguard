package token_test

import (
	"testing"

	"github.com/fotini85/tokenguard/internal/token"
)

// Verify runs on every authenticated request, so this is the price of
// not keeping sessions in a database.
//
// Most of it is not the HMAC. Compare this against the forged path
// below, which stops at the signature: the difference is the JSON
// decoder, and it is roughly two thirds of the total.
func BenchmarkVerify(b *testing.B) {
	c := token.NewCodec(key(1), clock(t0))
	raw, err := c.Sign(accessClaims())
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := c.Verify(raw, token.KindAccess); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerifyBadSignature(b *testing.B) {
	c := token.NewCodec(key(1), clock(t0))
	raw, err := c.Sign(accessClaims())
	if err != nil {
		b.Fatal(err)
	}
	forged := raw[:len(raw)-1] + "A"

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		c.Verify(forged, token.KindAccess) //nolint:errcheck // failure is the point
	}
}

// Sign happens once per login or refresh, not per request, so it is
// here for completeness rather than because it is hot.
func BenchmarkSign(b *testing.B) {
	c := token.NewCodec(key(1), clock(t0))
	cl := accessClaims()

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := c.Sign(cl); err != nil {
			b.Fatal(err)
		}
	}
}
