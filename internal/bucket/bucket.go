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

type Bucket struct {
	mu           sync.Mutex
	available    float64
	maxAvailable float64
	perSec       float64
	lastChecked  time.Time
}

func New(p Policy, now time.Time) *Bucket {
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
