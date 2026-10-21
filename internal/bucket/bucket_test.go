package bucket_test

import (
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

}
