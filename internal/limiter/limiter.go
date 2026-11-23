package limiter

// Package limiter keeps one token bucket per caller and puts a hard
// ceiling on how many it will hold.
//
// The ceiling is the whole point. Callers are not a bounded set: a
// single IPv6 subscriber is handed a /64, which is 18 quintillion
// addresses. Without a ceiling, one attacker adds one map entry per
// address until the process runs out of memory, and the rate limiter
// becomes the attack surface it was built to remove.

import (
	"sync"
	"time"

	"github.com/fotini85/tokenguard/internal/bucket"
)

type Config struct {
	Policy  bucket.Policy
	MaxKeys int
}

type Limiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket.Bucket

	policy  bucket.Policy
	maxKeys int

	// Two counters, not one. "this caller used up their allowance" is
	// ordinary traffic. "the map is full and I am turning strangers
	// away to stay alive" means something is attacking us. Counted
	// together, the second disappears into the noise of the first.
	deniedNoTokens   uint64
	deniedAtCapacity uint64
}

func New(cfg Config) *Limiter {
	if cfg.MaxKeys < 1 {
		panic("limiter: MaxKeys must be at least 1")
	}

	// Resolve the policy once, here, rather than letting each bucket do
	// it on creation. Two things follow.
	//
	// A policy that cannot work refuses to start, instead of panicking
	// on whichever request first happens to build a bucket — which under
	// a policy that only one route can violate might be a week later.
	//
	// And Remaining, which answers from the policy for a caller with no
	// bucket yet, reads the same ceiling the buckets do.
	policy := cfg.Policy.Normalise()

	return &Limiter{
		buckets: make(map[string]*bucket.Bucket),
		policy:  policy,
		maxKeys: cfg.MaxKeys,
	}
}

func (l *Limiter) Allow(key string, cost float64, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	b, ok := l.buckets[key]
	if !ok {
		if len(l.buckets) >= l.maxKeys {
			l.sweepLocked(now)
		}
		// Checked again: the sweep may have freed nothing, which is what
		// an active attack looks like.
		//
		// Refusing here turns away a caller who has spent nothing and
		// broken no limit. That is deliberate. The alternative — admit
		// them because the table is full — makes filling the table the
		// bypass: one map entry per address until there is no room, and
		// from that point everybody passes unmetered. A limiter that
		// fails open under pressure is not a limiter.
		//
		// The cost is that the refusal is indiscriminate. It does not
		// land on whoever filled the table, it lands on whoever arrives
		// next: attacker and new subscriber alike, same code, same
		// answer. And since the only eviction here is "drop the buckets
		// that are full", a caller who keeps their buckets drained keeps
		// their slot. Occupancy is first come, first served, with no
		// queue behind it.
		//
		// Both are accepted rather than fixed. Evicting a bucket that
		// still owes something would forgive that debt, which is the one
		// thing this table exists to prevent. And recency is the wrong
		// signal for choosing a victim: a caller serving out a 429 is
		// silent by construction, so an LRU would evict precisely the
		// callers being limited and hand them a full bucket on return.
		if len(l.buckets) >= l.maxKeys {
			l.deniedAtCapacity++
			return false
		}
		b = bucket.New(l.policy, now)
		l.buckets[key] = b
	}
	if !b.AllowNAt(cost, now) {
		l.deniedNoTokens++
		return false
	}
	return true

}

func (l *Limiter) Remaining(key string, now time.Time) int {
	l.mu.Lock()
	defer l.mu.Unlock()

	b, ok := l.buckets[key]
	if !ok {
		return l.policy.MaxAtOnce
	}
	return b.Remaining(now)
}

func (l *Limiter) sweepLocked(now time.Time) {
	for key, b := range l.buckets {
		if b.Remaining(now) >= l.policy.MaxAtOnce {
			delete(l.buckets, key)
		}

	}
}

// Limit is the ceiling a caller can hold at once, for the
// X-RateLimit-Limit header. Without it, a Remaining of 3 says nothing:
// three out of five is a healthy caller, three out of a hundred is one
// about to be refused.
//
// No lock. The policy is resolved in New and never written again, so
// there is nothing here that another goroutine could be changing.
func (l *Limiter) Limit() int { return l.policy.MaxAtOnce }

func (l *Limiter) Size() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.buckets)
}

func (l *Limiter) Stats() (noTokens, atCapacity uint64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.deniedNoTokens, l.deniedAtCapacity
}
