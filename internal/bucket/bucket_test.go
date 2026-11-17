package bucket_test

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/fotini85/tokenguard/internal/bucket"
)

var t0 = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

func TestAllowAt(t *testing.T) {
	tests := []struct {
		name   string
		policy bucket.Policy
		at     []time.Duration
		want   []bool
	}{
		{
			name:   "ξοδεύει ό,τι έχει και μετά αρνείται",
			policy: bucket.Policy{AllowedRequests: 1, Window: time.Second, MaxAtOnce: 3},
			at:     []time.Duration{0, 0, 0, 0},
			want:   []bool{true, true, true, false},
		},
		{
			name:   "ένα δευτερόλεπτο δίνει ένα request πίσω",
			policy: bucket.Policy{AllowedRequests: 1, Window: time.Second, MaxAtOnce: 2},
			at:     []time.Duration{0, 0, 0, time.Second},
			want:   []bool{true, true, false, true},
		},
		{
			name:   "τα κλάσματα δεν χάνονται",
			policy: bucket.Policy{AllowedRequests: 1, Window: time.Second, MaxAtOnce: 1},
			// Κάθε 400ms κερδίζει 0.4. Στα 1200ms έχει μαζέψει 1.2,
			// άρα μόνο το τελευταίο περνάει.
			at: []time.Duration{
				0,
				400 * time.Millisecond,
				800 * time.Millisecond,
				1200 * time.Millisecond,
			},
			want: []bool{true, false, false, true},
		},
		{
			name:   "η αδράνεια δεν μαζεύει άπειρα requests",
			policy: bucket.Policy{AllowedRequests: 10, Window: time.Second, MaxAtOnce: 2},
			// Μια ώρα αδράνειας θα έδινε 36000 requests χωρίς ταβάνι.
			// Με ταβάνι 2, μόνο δύο περνάνε.
			at:   []time.Duration{0, time.Hour, time.Hour, time.Hour},
			want: []bool{true, true, true, false},
		},
		{
			name:   "ο χρόνος προς τα πίσω δεν αφαιρεί requests",
			policy: bucket.Policy{AllowedRequests: 1, Window: time.Second, MaxAtOnce: 2},
			// Ξεκινάμε στο +1min, μετά πάμε πίσω στο t0.
			at:   []time.Duration{time.Minute, 0, 0},
			want: []bool{true, true, false},
		},
		{
			name:   "MaxAtOnce στο μηδέν παίρνει την τιμή του AllowedRequests",
			policy: bucket.Policy{AllowedRequests: 3, Window: time.Second},
			at:     []time.Duration{0, 0, 0, 0},
			want:   []bool{true, true, true, false},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := bucket.New(tt.policy, t0)

			for i, s := range tt.at {
				got := b.AllowAt(t0.Add(s))
				if got != tt.want[i] {
					t.Errorf("request %d at t0_%v AllowAt() = %v, want %v",
						i, s, got, tt.want[i])
				}
			}

		})

	}
}

func TestRemainingDoesNotConsume(t *testing.T) {
	p := bucket.Policy{AllowedRequests: 1, Window: time.Second, MaxAtOnce: 5}
	b := bucket.New(p, t0)

	for i := 0; i < 3; i++ {
		if got := b.Remaining(t0); got != 5 {
			t.Fatalf("Remaining() call %d = %d, want 5", i, got)
		}
	}

	allowed := 0
	for i := 0; i < 5; i++ {
		if b.AllowAt(t0) {
			allowed++
		}
	}
	if allowed != 5 {
		t.Errorf("allowed %d requests after three Remaining calls, want 5", allowed)
	}
}

func TestRemainingCountsDown(t *testing.T) {
	p := bucket.Policy{AllowedRequests: 1, Window: time.Second, MaxAtOnce: 3}
	b := bucket.New(p, t0)

	for i, want := range []int{3, 2, 1, 0} {
		if got := b.Remaining(t0); got != want {
			t.Errorf("after %d requests: Remaining() = %d, want %d", i, got, want)
		}
		b.AllowAt(t0)
	}
}

// Remaining has to bring the bucket up to date before answering, or it
// reports the balance as of the last request rather than as of now.
func TestRemainingCreditsElapsedTime(t *testing.T) {
	p := bucket.Policy{AllowedRequests: 2, Window: time.Second, MaxAtOnce: 4}
	b := bucket.New(p, t0)

	for i := 0; i < 4; i++ {
		b.AllowAt(t0)
	}
	if got := b.Remaining(t0); got != 0 {
		t.Fatalf("Remaining() at t0 = %d, want 0", got)
	}

	if got := b.Remaining(t0.Add(time.Second)); got != 2 {
		t.Errorf("Remaining() at t0+1s = %d, want 2", got)
	}
}

// Exactly MaxAtOnce requests pass in one instant, not one more. Catches
// an off-by-one in the available < n comparison.
func TestExactCeiling(t *testing.T) {
	const ceiling = 20
	p := bucket.Policy{AllowedRequests: 1, Window: time.Second, MaxAtOnce: ceiling}
	b := bucket.New(p, t0)

	allowed := 0
	for i := 0; i < 100; i++ {
		if b.AllowAt(t0) {
			allowed++
		}
	}
	if allowed != ceiling {
		t.Errorf("allowed = %d, want %d", allowed, ceiling)
	}
}

func TestPolicyNormalise(t *testing.T) {
	t.Run("zero MaxAtOnce takes AllowedRequests", func(t *testing.T) {
		got := bucket.Policy{AllowedRequests: 7, Window: time.Second}.Normalise()
		if got.MaxAtOnce != 7 {
			t.Errorf("MaxAtOnce = %d, want 7", got.MaxAtOnce)
		}
	})

	t.Run("the caller's copy is untouched", func(t *testing.T) {
		p := bucket.Policy{AllowedRequests: 7, Window: time.Second}
		p.Normalise()
		if p.MaxAtOnce != 0 {
			t.Errorf("Normalise mutated the receiver: MaxAtOnce = %d, want 0", p.MaxAtOnce)
		}
	})

	bad := []struct {
		name   string
		policy bucket.Policy
	}{
		{"no requests", bucket.Policy{AllowedRequests: 0, Window: time.Second}},
		{"negative requests", bucket.Policy{AllowedRequests: -1, Window: time.Second}},
		{"zero window", bucket.Policy{AllowedRequests: 1, Window: 0}},
		{"negative window", bucket.Policy{AllowedRequests: 1, Window: -time.Second}},
		{"negative MaxAtOnce", bucket.Policy{AllowedRequests: 1, Window: time.Second, MaxAtOnce: -1}},
		{"negative MaxCost", bucket.Policy{AllowedRequests: 1, Window: time.Second, MaxCost: -1}},
		{
			// The point of declaring MaxCost at all: a request costing
			// more than the bucket can ever hold is refused for the
			// lifetime of the process, so say so at startup.
			name:   "MaxCost above the ceiling",
			policy: bucket.Policy{AllowedRequests: 1, Window: time.Second, MaxAtOnce: 5, MaxCost: 6},
		},
	}

	for _, tt := range bad {
		t.Run(tt.name, func(t *testing.T) {
			// recover() returns nil when nothing panicked, so nil here
			// means Normalise accepted a policy it should have rejected.
			defer func() {
				if recover() == nil {
					t.Error("Normalise() did not panic")
				}
			}()
			tt.policy.Normalise()
		})
	}

	t.Run("MaxCost equal to the ceiling is fine", func(t *testing.T) {
		bucket.Policy{AllowedRequests: 1, Window: time.Second, MaxAtOnce: 5, MaxCost: 5}.Normalise()
	})
}

// A cost above the ceiling is not a busy bucket, it is a bucket that can
// never pay. Refusing quietly would hide the misconfiguration behind a
// 429 that never clears.
func TestAllowNAtPanicsOnUnaffordableCost(t *testing.T) {
	b := bucket.New(bucket.Policy{AllowedRequests: 1, Window: time.Second, MaxAtOnce: 5}, t0)

	defer func() {
		if recover() == nil {
			t.Error("AllowNAt() returned instead of panicking")
		}
	}()
	b.AllowNAt(6, t0)
}

func TestAllowNAtPanicsOnNonPositiveCost(t *testing.T) {
	for _, n := range []float64{0, -1} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			b := bucket.New(bucket.Policy{AllowedRequests: 1, Window: time.Second}, t0)
			defer func() {
				if recover() == nil {
					t.Error("AllowNAt() returned instead of panicking")
				}
			}()
			b.AllowNAt(n, t0)
		})
	}
}

// Nothing here asserts an outcome, deliberately: with several goroutines
// the result is not deterministic. It exists so that concurrent accesses
// happen at all, for the race detector to look at.
//
//	go test -race ./internal/bucket
func TestConcurrentAccess(t *testing.T) {
	p := bucket.Policy{AllowedRequests: 100, Window: time.Second, MaxAtOnce: 100}
	b := bucket.New(p, t0)

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			b.AllowAt(t0)
			b.Remaining(t0)
		}()
	}
	wg.Wait()
}
