package bloom_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/fotini85/tokenguard/internal/bloom"
)

var benchStart = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

// The answer that matters. Nearly every request asks whether a session
// was revoked, nearly every answer is no, and a no costs this much
// instead of a round trip to Postgres.
func BenchmarkRotatingMayContainMiss(b *testing.B) {
	r := bloom.NewRotating(10_000, 0.01, 10*time.Minute, benchStart)
	for i := 0; i < 1_000; i++ {
		r.Add(fmt.Sprintf("session-%d", i), benchStart)
	}

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		r.MayContain("not-in-here", benchStart)
	}
}

func BenchmarkRotatingAdd(b *testing.B) {
	r := bloom.NewRotating(1_000_000, 0.01, 10*time.Minute, benchStart)

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		r.Add("session-id-of-a-realistic-length", benchStart)
	}
}

// Against the plain filter, to show what the rotation itself costs:
// the write lock MayContain has to take, because a read can be the
// thing that triggers a rotation.
func BenchmarkFilterMayContainMiss(b *testing.B) {
	f := bloom.New(10_000, 0.01)
	for i := 0; i < 1_000; i++ {
		f.Add(fmt.Sprintf("session-%d", i))
	}

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		f.MayContain("not-in-here")
	}
}
