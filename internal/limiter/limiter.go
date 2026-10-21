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
	return &Limiter{
		buckets: make(map[string]*bucket.Bucket),
		policy:  cfg.Policy,
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
		//Checked again: the sweep may have freed nothing, which is
		// what an active attack looks like.
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
