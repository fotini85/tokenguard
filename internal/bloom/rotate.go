package bloom

import (
	"sync"
	"time"
)

// Rotating is a pair of filters that take turns, so entries expire.
//
// A bloom filter cannot delete: clearing the bits for one element would
// clear bits that other elements share. The way round it is to keep two
// filters and throw the older one away.
//
// Writes go to the current filter; reads consult both. When the window
// elapses the previous filter is dropped, the current becomes previous,
// and a fresh one takes over. Every entry therefore survives at least
// one full window and at most two.
//
// A single filter cleared in place would be wrong: at the moment of
// clearing, a revocation made a second earlier would vanish and the
// token it revoked would start working again.
//
// Set the window to the access token TTL. A revocation older than that
// is pointless: the token it refers to has already expired on its own,
// and the codec rejects it before this is ever consulted.
type Rotating struct {
	mu       sync.RWMutex
	current  *Filter
	previous *Filter

	n        int
	p        float64
	window   time.Duration
	rotateAt time.Time
}

// NewRotating builds a rotating pair sized for n entries per window at
// a false positive rate of p.
func NewRotating(n int, p float64, window time.Duration, now time.Time) *Rotating {
	if window <= 0 {
		panic("bloom: window must be positive")
	}
	return &Rotating{
		current:  New(n, p),
		previous: New(n, p),
		n:        n,
		p:        p,
		window:   window,
		rotateAt: now.Add(window),
	}
}

// Add records s in the current filter.
func (r *Rotating) Add(s string, now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.rotateIfDueLocked(now)
	r.current.Add(s)
}

// MayContain reports whether s might be present in either filter.
//
// False is certain and needs nothing further. True means "ask the
// database" — it is never a decision on its own.
//
// This takes the write lock even though it only reads, because a read
// can trigger a rotation. Checking under RLock and upgrading would
// leave a window where two goroutines both decide to rotate, and the
// second would discard a filter the first had just promoted.
func (r *Rotating) MayContain(s string, now time.Time) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.rotateIfDueLocked(now)
	return r.current.MayContain(s) || r.previous.MayContain(s)
}

// rotateIfDueLocked advances the pair if the window has elapsed.
//
// rotateAt is simply the next appointment, set one window ahead each
// time. It has nothing to do with when any particular entry was
// written: the pair moves on a fixed cadence and entries expire as a
// side effect of the filter holding them being dropped.
//
// This runs on whichever goroutine happens to call in, rather than on a
// timer: no background goroutine to manage, and a filter nobody touches
// costs nothing to maintain.
//
// A long idle period may span several windows. Two rotations empty both
// filters, so looping further would change nothing.
//
// The caller must hold r.mu.
func (r *Rotating) rotateIfDueLocked(now time.Time) {
	if now.Before(r.rotateAt) {
		return
	}

	elapsed := now.Sub(r.rotateAt)
	skipped := int(elapsed/r.window) + 1

	if skipped >= 2 {
		// Everything in both filters has expired. Start clean.
		r.current = New(r.n, r.p)
		r.previous = New(r.n, r.p)
	} else {
		r.previous = r.current
		r.current = New(r.n, r.p)
	}

	r.rotateAt = now.Add(r.window)
}

// Stats reports how many entries each filter holds, for monitoring.
//
// A current filter well past the n it was sized for means the false
// positive rate has drifted above p, and the sizing needs revisiting.
func (r *Rotating) Stats() (current, previous int) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.current.Len(), r.previous.Len()
}
