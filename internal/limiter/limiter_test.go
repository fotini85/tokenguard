package limiter_test

import (
	"sync"
	"testing"
	"time"

	"github.com/fotini85/tokenguard/internal/bucket"
	"github.com/fotini85/tokenguard/internal/limiter"
)

var t0 = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

func newLimiter(maxKeys int, p bucket.Policy) *limiter.Limiter {
	return limiter.New(limiter.Config{Policy: p, MaxKeys: maxKeys})
}

func TestAllowCountsEachKeySeparately(t *testing.T) {
	l := newLimiter(10, bucket.Policy{AllowedRequests: 1, Window: time.Second, MaxAtOnce: 2})

	// Two requests from one caller exhaust that caller and nobody else.
	if !l.Allow("a", 1, t0) || !l.Allow("a", 1, t0) {
		t.Fatal("the first two requests from a were refused")
	}
	if l.Allow("a", 1, t0) {
		t.Error("a was allowed a third request")
	}
	if !l.Allow("b", 1, t0) {
		t.Error("b was refused because a had spent its allowance")
	}
}

func TestRemainingAnswersBeforeABucketExists(t *testing.T) {
	// MaxAtOnce left at zero on purpose: bucket.New reads that as "the
	// same as AllowedRequests", and the limiter has to agree. Reporting
	// nought remaining to a caller whose bucket would be full is the
	// bug this guards.
	l := newLimiter(10, bucket.Policy{AllowedRequests: 5, Window: time.Second})

	if got := l.Remaining("nobody", t0); got != 5 {
		t.Errorf("Remaining() for an unknown key = %d, want 5", got)
	}
	if got := l.Limit(); got != 5 {
		t.Errorf("Limit() = %d, want 5", got)
	}
	if got := l.Size(); got != 0 {
		t.Errorf("Size() = %d, want 0: asking should not create a bucket", got)
	}
}

func TestAllowChargesTheWeightedCost(t *testing.T) {
	l := newLimiter(10, bucket.Policy{
		AllowedRequests: 1, Window: time.Second, MaxAtOnce: 10, MaxCost: 10,
	})

	if !l.Allow("a", 10, t0) {
		t.Fatal("a request costing exactly the ceiling was refused")
	}
	if l.Allow("a", 1, t0) {
		t.Error("a request was allowed on an emptied bucket")
	}
	if got := l.Remaining("a", t0); got != 0 {
		t.Errorf("Remaining() = %d, want 0", got)
	}
}

// The ceiling on keys is what stops the limiter becoming the attack it
// was built to prevent: callers are not a bounded set, and one entry
// per address runs the process out of memory.
func TestMaxKeysRefusesStrangersWhenFull(t *testing.T) {
	l := newLimiter(2, bucket.Policy{AllowedRequests: 1, Window: time.Second, MaxAtOnce: 2})

	// Two keys, each with something spent, so neither can be swept.
	l.Allow("a", 1, t0)
	l.Allow("b", 1, t0)

	if l.Allow("c", 1, t0) {
		t.Error("a third key was admitted past MaxKeys")
	}
	if got := l.Size(); got != 2 {
		t.Errorf("Size() = %d, want 2", got)
	}

	// Under pressure the table keeps whoever is already in it. That
	// includes an attacker who arrived first — but their limit still
	// applies, so what they hold is a seat, not a privilege. Evicting
	// instead would let them push legitimate callers out and reset
	// their own allowance by doing so.
	if !l.Allow("a", 1, t0) {
		t.Error("a caller already in the table was refused while it was full")
	}
}

// Sweeping is semantically free: a full bucket and a bucket that does
// not exist allow exactly the same thing, so dropping full ones loses
// no state.
func TestSweepReclaimsFullBuckets(t *testing.T) {
	l := newLimiter(2, bucket.Policy{AllowedRequests: 1, Window: time.Second, MaxAtOnce: 2})

	l.Allow("a", 1, t0)
	l.Allow("b", 1, t0)

	// Long enough for both to refill to the ceiling.
	later := t0.Add(time.Hour)

	if !l.Allow("c", 1, later) {
		t.Fatal("c was refused even though the table was full of idle callers")
	}
	if got := l.Size(); got != 1 {
		t.Errorf("Size() = %d, want 1: the swept buckets were not dropped", got)
	}
}

// Two counters, not one. "this caller used up their allowance" is
// ordinary traffic; "the table is full and strangers are being turned
// away to keep the process alive" means something is attacking. Added
// together, the second disappears into the noise of the first.
func TestStatsSeparatesTheTwoReasonsForRefusing(t *testing.T) {
	l := newLimiter(1, bucket.Policy{AllowedRequests: 1, Window: time.Second, MaxAtOnce: 1})

	l.Allow("a", 1, t0) // admitted, empties a
	l.Allow("a", 1, t0) // refused: no tokens
	l.Allow("b", 1, t0) // refused: table full

	noTokens, atCapacity := l.Stats()
	if noTokens != 1 {
		t.Errorf("deniedNoTokens = %d, want 1", noTokens)
	}
	if atCapacity != 1 {
		t.Errorf("deniedAtCapacity = %d, want 1", atCapacity)
	}
}

func TestNewPanicsOnBadConfig(t *testing.T) {
	good := bucket.Policy{AllowedRequests: 1, Window: time.Second}

	tests := []struct {
		name string
		cfg  limiter.Config
	}{
		{"no keys allowed", limiter.Config{Policy: good, MaxKeys: 0}},
		{"negative keys", limiter.Config{Policy: good, MaxKeys: -1}},
		// Resolved here rather than on the first request that happens
		// to build a bucket, which under a policy only one route can
		// reach might be a week later.
		{"policy that cannot work", limiter.Config{
			Policy:  bucket.Policy{AllowedRequests: 1, Window: 0},
			MaxKeys: 1,
		}},
		{"cost nothing can afford", limiter.Config{
			Policy:  bucket.Policy{AllowedRequests: 1, Window: time.Second, MaxAtOnce: 2, MaxCost: 3},
			MaxKeys: 1,
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Error("New() did not panic")
				}
			}()
			limiter.New(tt.cfg)
		})
	}
}

// No assertions, deliberately: with several goroutines the outcome is
// not deterministic. This exists so concurrent access happens at all,
// for the race detector to look at.
//
//	go test -race ./internal/limiter
func TestConcurrentAccess(t *testing.T) {
	l := newLimiter(64, bucket.Policy{AllowedRequests: 100, Window: time.Second, MaxAtOnce: 100})

	keys := []string{"a", "b", "c", "d"}

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			k := keys[i%len(keys)]
			l.Allow(k, 1, t0)
			l.Remaining(k, t0)
			l.Size()
			l.Stats()
		}(i)
	}
	wg.Wait()
}
