package token

import "time"

// Kind distinguishes what a token is for. It is checked on every
// verify, not just parsed.
//
// Without it, a token minted for one purpose can be presented for
// another. This is the same class of bug as JWT's "alg: none": the
// signature is valid, so the check passes, and the caller ends up
// treating an anonymous rate-limit token as proof of identity.
type Kind uint8

const (
	KindAnon   Kind = iota + 1 //anonymous
	KindAccess                 //signed-in

)

type Claims struct {
	Kind      Kind
	IssuedAt  time.Time
	ExpiresAt time.Time

	//KindAccess
	UserID    string
	SessionID string

	// Set for KindAnon only: the rate limit state we do not want to
	// keep server side, because anonymous callers are an unbounded set.
	Available float64
	LastSeen  time.Time
}
