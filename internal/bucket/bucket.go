package bucket

import (
	"sync"
	"time"
)

type Policy struct {
	AllowedRequests int
	Window          time.Duration
	MaxAtOnce       int

	// MaxCost is the largest value that will ever be passed to
	// AllowNAt. Declared here so New can refuse a policy where some
	// requests could never be affordable, instead of that showing up
	// later as users being refused for no visible reason.
	MaxCost float64
}

// Normalise fills in the fields a caller may leave at zero and panics on
// a policy that could never work. It takes and returns a value, so the
// caller's own copy is untouched.
//
// Separate from New because New is not the only place that needs the
// resolved form. A limiter answers Remaining from the policy when a
// caller has no bucket yet, and reading MaxAtOnce there while New
// resolved it here would be the same rule written twice: a policy with
// MaxAtOnce left at zero would report nought remaining to a caller whose
// bucket, once built, is full.
//
// Panics rather than returning an error. Every one of these is a wiring
// mistake, fixed by editing the program, and a limiter that resolves its
// policy at construction turns all of them into a refusal to start
// instead of a surprise on whichever request first builds a bucket.
func (p Policy) Normalise() Policy {
	if p.AllowedRequests < 1 {
		panic("bucket: AllowedRequests must be at least 1")
	}
	if p.Window <= 0 {
		panic("bucket: Window must be positive")
	}
	if p.MaxAtOnce == 0 {
		p.MaxAtOnce = p.AllowedRequests
	}
	if p.MaxAtOnce < 1 {
		panic("bucket: MaxAtOnce cannot be negative")
	}
	if p.MaxCost < 0 {
		panic("bucket: MaxCost cannot be negative")
	}

	// Zero means undeclared, so there is nothing to check against. A
	// declared cost above the ceiling is the thing worth catching: it
	// describes a request that can never be afforded, which would show
	// up as one endpoint answering 429 forever with nothing in the logs
	// to say why.
	if p.MaxCost > float64(p.MaxAtOnce) {
		panic("bucket: MaxCost exceeds MaxAtOnce, so a request costing that much could never pass")
	}

	return p
}

type Bucket struct {
	mu           sync.Mutex
	available    float64
	maxAvailable float64
	perSec       float64
	lastChecked  time.Time
}

func New(p Policy, now time.Time) *Bucket {
	p = p.Normalise()

	return &Bucket{
		available:    float64(p.MaxAtOnce),
		maxAvailable: float64(p.MaxAtOnce),
		perSec:       float64(p.AllowedRequests) / p.Window.Seconds(),
		lastChecked:  now,
	}
}

// AllowNAt spends n requests worth of allowance instead of one, and
// reports whether there was enough.
//
// Requests do not all cost the same. A login runs bcrypt and burns
// around 100ms of CPU; a cached GET costs almost nothing. Charging both
// a flat one lets the expensive ones through at the same rate as the
// cheap ones, which is exactly backwards.
//
// n must not exceed Policy.MaxAtOnce, or the request can never pass:
// available is capped at maxAvailable, so a cost above that ceiling is
// permanently unaffordable no matter how long the caller waits.
func (b *Bucket) AllowNAt(n float64, now time.Time) bool {
	if n <= 0 {
		panic("bucket: cost must be positive")
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	if n > b.maxAvailable {
		panic("bucket: cost exceeds the bucket ceiling, so it could never be paid")
	}

	b.creditElapsedLocked(now)

	if b.available < n {
		return false
	}
	b.available -= n
	return true
}

// AllowAt spends one request worth of allowance.
func (b *Bucket) AllowAt(now time.Time) bool {
	return b.AllowNAt(1, now)
}

func (b *Bucket) creditElapsedLocked(now time.Time) {
	elapsed := now.Sub(b.lastChecked)

	if elapsed <= 0 {
		b.lastChecked = now
		return

	}

	b.available += elapsed.Seconds() * b.perSec

	if b.available > b.maxAvailable {
		b.available = b.maxAvailable
	}

	b.lastChecked = now

}

func (b *Bucket) Remaining(now time.Time) int {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.creditElapsedLocked(now)
	return int(b.available)
}
