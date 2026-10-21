package bloom

import "testing"

func TestNextPow2(t *testing.T) {
	tests := []struct{ in, want uint64 }{
		{0, 1},
		{1, 1},
		{2, 2},
		{3, 4},
		{5, 8},
		{100, 128},
		{128, 128}, // ήδη δύναμη του 2
		{129, 256},
		{143776, 262144},
	}
	for _, tt := range tests {
		if got := nextPow2(tt.in); got != tt.want {
			t.Errorf("nextPow2(%d) = %d, want %d", tt.in, got, tt.want)
		}
	}
}

// Whatever sizing New is given, m must come out a power of two,
// because index masks instead of dividing.
func TestFilterSizeIsPowerOfTwo(t *testing.T) {
	for _, n := range []int{1, 10, 1000, 10000, 100000} {
		for _, p := range []float64{0.5, 0.01, 0.001, 0.0001} {
			f := New(n, p)
			if f.m&(f.m-1) != 0 {
				t.Errorf("New(%d, %v): m = %d, not a power of two", n, p, f.m)
			}
		}
	}
}
