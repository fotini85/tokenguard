package authmw

import (
	"context"

	token "github.com/fotini85/tokenguard/internal/token"
)

type ctxKey struct{}

var identityKey ctxKey

type Identity struct {
	Authenticated bool

	UserID    string
	SessionID string

	RateKey string //logging
}

// unexported for middleware
func withIdentity(ctx context.Context, id Identity) context.Context {
	return context.WithValue(ctx, identityKey, id)
}

func IdentityFrom(ctx context.Context) (Identity, bool) {
	id, ok := ctx.Value(identityKey).(Identity)
	return id, ok

}

// exported for handlers
func MustIdentity(ctx context.Context) Identity {
	id, ok := IdentityFrom(ctx)
	if !ok {
		panic("authmw: no identity in context; handler mounted outside the middleware")
	}
	return id
}

// claims to auth transition:only what a handler needs(Identity)
func claimsToIdentity(cl token.Claims, rateKey string) Identity {
	return Identity{
		Authenticated: true,
		UserID:        cl.UserID,
		SessionID:     cl.SessionID,
		RateKey:       rateKey,
	}
}
