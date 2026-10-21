package limiter

import "net/netip"

// KeyForAddr builds the rate limiting key for a client address.
//
// IPv4 is used whole: a subscriber normally has exactly one address, so
// it already identifies a household.
//
// IPv6 is truncated to its first 64 bits. Subscribers are handed a /64
// block, and every address in it belongs to the same household. Keying
// on the full address would let one subscriber look like 18 quintillion
// separate callers: they would never reach a limit, and every request
// would add a map entry until memory ran out.
//
// /64 is the right cut. Wider, at /48, would put unrelated subscribers
// of the same provider in one bucket, so one could lock out the others.
// Narrower would leave an attacker billions of distinct keys inside
// their own allocation.
func KeyForAddr(addr netip.Addr) string {
	// An IPv4 address can arrive wrapped as ::ffff:1.2.3.4. Without
	// unwrapping, Is4 reports false and we would truncate something
	// that is really IPv4, giving one caller two different keys
	// depending on how the connection was made.
	addr = addr.Unmap()

	if addr.Is4() {
		return addr.String()
	}

	p, err := addr.Prefix(64)
	if err != nil {
		// Cannot happen for a valid v6 address. Falling back to the
		// full address is the safe direction: worse grouping, never
		// weaker limiting.
		return addr.String()
	}
	return p.String()
}
