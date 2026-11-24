package bloom_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/fotini85/tokenguard/internal/bloom"
)

// benchNow is the clock the rotating benchmarks run on: fixed, so no
// rotation happens mid-measurement and every iteration costs the same.
func benchNow() time.Time { return benchStart }

var benchStart = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

// The answer that matters. Nearly every request asks whether a session
// was revoked, nearly every answer is no, and a no costs this much
// instead of a round trip to Postgres.
func BenchmarkRotatingMayContainMiss(b *testing.B) {
	r := bloom.NewRotating(10_000, 0.01, 10*time.Minute, benchNow)
	for i := 0; i < 1_000; i++ {
		r.Add(fmt.Sprintf("session-%d", i))
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r.MayContain("not-in-here")
	}
}

func BenchmarkRotatingAdd(b *testing.B) {
	r := bloom.NewRotating(1_000_000, 0.01, 10*time.Minute, benchNow)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r.Add("session-id-of-a-realistic-length")
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
