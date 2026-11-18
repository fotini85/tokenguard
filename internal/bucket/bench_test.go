package bucket_test

import (
	"testing"
	"time"

	"github.com/fotini85/tokenguard/internal/bucket"
)

// The hot path: one uncontended request. Whatever this costs is paid
// by every request the server ever answers, so it is the number worth
// knowing.
func BenchmarkAllowAt(b *testing.B) {
	bk := bucket.New(bucket.Policy{AllowedRequests: 1_000_000, Window: time.Second}, t0)
	now := t0

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		// Time has to move, or every call after the first takes the
		// elapsed <= 0 shortcut and the refill arithmetic is never
		// measured.
		now = now.Add(time.Microsecond)
		bk.AllowAt(now)
	}
}

// The refused path, which is the one an attacker drives. It must not
// be slower than the allowed path, or being refused costs us more than
// answering would have.
func BenchmarkAllowAtRefused(b *testing.B) {
	bk := bucket.New(bucket.Policy{AllowedRequests: 1, Window: time.Hour, MaxAtOnce: 1}, t0)
	bk.AllowAt(t0) // empty it

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		bk.AllowAt(t0)
	}
}

// Under contention the mutex is the whole cost. A bucket is per
// caller, so real contention means one caller on many connections.
func BenchmarkAllowAtParallel(b *testing.B) {
	bk := bucket.New(bucket.Policy{AllowedRequests: 1_000_000, Window: time.Second}, t0)

	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			bk.AllowAt(t0)
		}
	})
}
