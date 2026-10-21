// Package bloom provides a set that answers one question — have I seen
// this before — in constant space, trading exactness for size.
//
// A negative answer is certain: an element that was added is never
// reported missing. A positive answer is probabilistic: an element that
// was never added may still be reported present.
//
// That asymmetry decides where this is safe to use. As a denylist of
// revoked sessions it is the right way round: a false positive costs
// one database lookup to confirm, never a wrong decision. Used the
// other way — to prove something is absent — it would silently accept
// revoked tokens, so don't.
package bloom

import (
	"hash/maphash"
	"math"
)

// Filter is one bloom filter. Not safe for concurrent use on its own;
// Rotating wraps it with the locking.
type Filter struct {
	bits []uint64 // the bit array, 64 bits per word
	m    uint64   // number of bits, always a power of two
	k    int      // how many bits each element sets
	s1   maphash.Seed
	s2   maphash.Seed
	n    int // elements added, for diagnostics
}

// New sizes a filter for n elements at a false positive rate of p.
//
//	m = -n·ln(p) / (ln2)²
//	k = (m/n)·ln2
//
// m is rounded up to a power of two so the modulo in index becomes a
// bitmask. That wastes some memory — 143,776 bits becomes 262,144 —
// and buys a single-cycle AND in place of a ~25-cycle division, on
// every one of the k probes of every lookup.
//
// Seeds come from maphash, which Go randomises per process. Fixed
// hashes would let an attacker work out offline which identifiers
// collide and then feed in values that produce false positives on
// demand, forcing a database lookup on every request and removing the
// reason this exists. With a per-process seed there is nothing to
// precompute.
func New(n int, p float64) *Filter {
	if n < 1 {
		panic("bloom: n must be at least 1")
	}
	if p <= 0 || p >= 1 {
		panic("bloom: p must be between 0 and 1")
	}

	mf := -float64(n) * math.Log(p) / (math.Ln2 * math.Ln2)
	m := nextPow2(uint64(math.Ceil(mf)))

	k := int(math.Round(float64(m) / float64(n) * math.Ln2))
	if k < 1 {
		k = 1
	}
	if k > 16 {
		// Past this the improvement is lost in the noise while every
		// lookup pays for the extra probes.
		k = 16
	}

	return &Filter{
		bits: make([]uint64, m/64),
		m:    m,
		k:    k,
		s1:   maphash.MakeSeed(),
		s2:   maphash.MakeSeed(),
	}
}

// Add records s by setting its k bits.
func (f *Filter) Add(s string) {
	h1 := maphash.String(f.s1, s)
	h2 := maphash.String(f.s2, s)

	for i := 0; i < f.k; i++ {
		idx := f.index(h1, h2, i)

		// idx/64 picks the word, idx%64 the bit inside it.
		// OR sets that one bit and leaves every other bit alone.
		f.bits[idx/64] |= 1 << (idx % 64)
	}
	f.n++
}

// MayContain reports whether s might have been added.
//
// False is certain. True may be wrong: the k bits could all have been
// set by other elements that happened to land on them.
func (f *Filter) MayContain(s string) bool {
	h1 := maphash.String(f.s1, s)
	h2 := maphash.String(f.s2, s)

	for i := 0; i < f.k; i++ {
		idx := f.index(h1, h2, i)

		// AND with the mask keeps only that bit. Zero means it was
		// never set, and one clear bit is proof the element is absent.
		if f.bits[idx/64]&(1<<(idx%64)) == 0 {
			return false
		}
	}
	return true
}

// index derives the i-th bit position for an element from its two
// hashes. Add and MayContain both call it, so the two agree by
// construction: computing this inline in each would let one drift from
// the other, and the filter would stop finding what it had stored
// without ever failing loudly.
//
// Kirsch and Mitzenmacher showed that g(i) = h1 + i·h2 gives the same
// false positive rate as k independent hash functions. So h1 is the
// starting point, h2 the stride, and k positions cost two passes over
// the input rather than k: around 72ns for a 36-character id instead
// of 360ns, on every request.
//
// The mask stands in for a modulo, which is only correct because m is
// a power of two.
func (f *Filter) index(h1, h2 uint64, i int) uint64 {
	return (h1 + uint64(i)*h2) & (f.m - 1)
}

// Len reports how many elements have been added.
func (f *Filter) Len() int { return f.n }

// nextPow2 returns the smallest power of two that is at least v.
//
// The shifts fill in every bit below the highest set one, doubling how
// much is filled each time, so six steps cover all 64 bits. Adding one
// to a run of ones then carries into the next bit up, which is a power
// of two by definition.
//
// The initial decrement handles a v that is already a power of two:
// without it, 128 would fill to 255 and come back as 256.
func nextPow2(v uint64) uint64 {
	if v == 0 {
		return 1
	}
	v--
	v |= v >> 1
	v |= v >> 2
	v |= v >> 4
	v |= v >> 8
	v |= v >> 16
	v |= v >> 32
	return v + 1
}
