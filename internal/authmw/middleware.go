package authmw

import (
	"context"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/fotini85/tokenguard/internal/apperr"
	"github.com/fotini85/tokenguard/internal/bloom"
	"github.com/fotini85/tokenguard/internal/limiter"
	"github.com/fotini85/tokenguard/internal/token"
)

// for db lookup after a blooms "maybe"
// contract here (dependency tree should move down)
// ctx to track I/O
type RevocationStore interface {
	IsRevoked(ctx context.Context, sessionID string) (bool, error)
}

type Config struct {
	Codec     *token.Codec
	IPLimit   *limiter.Limiter //unbounded
	UserLimit *limiter.Limiter //strict
	Denylist  *bloom.Rotating
	Revoked   RevocationStore

	// TrustedProxyHops is how many proxies of ours sit in front of this
	// server. Zero ignores X-Forwarded-For entirely, which is the right
	// default: on a port a caller can reach directly, the header is
	// input from a stranger, and honouring it hands out a fresh identity
	// per request.
	//
	// One knob, not two. A separate TrustProxy bool alongside it would
	// mean two things to keep in step, and someone setting only the bool
	// would believe they had turned the header on.
	TrustedProxyHops int
	Cost             func(*http.Request) float64
	Now              func() time.Time
}

type Middleware struct {
	cfg Config
}

// construct
func New(cfg Config) *Middleware {
	if cfg.Codec == nil || cfg.IPLimit == nil || cfg.UserLimit == nil {
		panic("authmw: Codec, IPLimit and UserLimit are required")
	}

	// Revocation checking is on or off. Half of it is a wiring mistake,
	// and both halves fail in ways nobody would notice at startup.
	//
	// A Denylist with no store to confirm its maybes dereferences a nil
	// interface inside a request, on the first bloom hit — which is the
	// first time anyone revokes anything, long after deployment.
	//
	// A store with no Denylist is quieter and worse: nothing ever
	// consults it, so revoked sessions keep working until their access
	// tokens expire, and the wiring looks correct the whole time.
	if (cfg.Denylist == nil) != (cfg.Revoked == nil) {
		panic("authmw: Denylist and Revoked must be supplied together")
	}

	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Cost == nil {
		cfg.Cost = func(*http.Request) float64 { return 1 }
	}
	return &Middleware{cfg: cfg}
}

func (m *Middleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		now := m.cfg.Now() //inject time once here
		id, err := m.resolve(r, now)
		if err != nil {
			apperr.Write(w, err)
			return
		}
		w.Header().Set("X-RateLimit-Remaining",
			strconv.Itoa(m.remaining(id, now)))
		next.ServeHTTP(w, r.WithContext(withIdentity(r.Context(), id)))
	})
}

func bearerToken(r *http.Request) string {
	const p = "Bearer "
	h := r.Header.Get("Authorization")
	if len(h) < len(p) || !strings.EqualFold(h[:len(p)], p) {
		return ""
	}
	return h[len(p):]
}

func (m *Middleware) remaining(id Identity, now time.Time) int {
	if id.Authenticated {
		return m.cfg.UserLimit.Remaining(id.RateKey, now)
	}
	return m.cfg.IPLimit.Remaining(id.RateKey, now)
}

func (m *Middleware) resolve(r *http.Request, now time.Time) (Identity, error) {
	const op = "authmw.resolve"
	addr, err := clientAddr(r, m.cfg.TrustedProxyHops)
	if err != nil {
		return Identity{}, apperr.E(op, apperr.KindMalformed, err)
	}
	ipKey := limiter.KeyForAddr(addr)
	cost := m.cfg.Cost(r)
	//both users limit:known and unknown
	if !m.cfg.IPLimit.Allow(ipKey, cost, now) {
		return Identity{}, apperr.E(op, apperr.KindRateLimited, nil)
	}
	//fall to anonymus if no token
	raw := bearerToken(r)
	if raw == "" {
		return Identity{RateKey: ipKey}, nil
	}
	// A token of the wrong kind is refused here even though its
	// signature is perfectly valid. An anonymous token is handed out to
	// anyone who asks, so accepting one as proof of identity would let
	// anyone be anyone.
	cl, err := m.cfg.Codec.Verify(raw, token.KindAccess)
	if err != nil {
		return Identity{}, apperr.E(op, apperr.KindOf(err), err)
	}
	if m.cfg.Denylist != nil && m.cfg.Denylist.MayContain(cl.SessionID, now) {
		revoked, err := m.cfg.Revoked.IsRevoked(r.Context(), cl.SessionID)
		if err != nil {
			return Identity{}, apperr.E(op, apperr.KindInternal, err)
		}
		if revoked {
			return Identity{}, apperr.E(op, apperr.KindRevoked, nil)
		}
	}
	userKey := "user:" + cl.UserID
	if !m.cfg.UserLimit.Allow(userKey, cost, now) {
		return Identity{}, apperr.E(op, apperr.KindRateLimited, nil)
	}

	return claimsToIdentity(cl, userKey), nil
}

const maxXFEntries = 16

func clientAddr(r *http.Request, trustedHops int) (netip.Addr, error) {
	if trustedHops <= 0 {
		return addrFromRemoteAddr(r)
	}

	xff := r.Header.Get("X-Forwarded-For")
	if xff == "" {
		return addrFromRemoteAddr(r)
	}

	// Split one past the cap, not at it. SplitN returns at most n
	// elements and crams the rest into the last one, so splitting at
	// maxXFEntries makes len(parts) > maxXFEntries impossible and the
	// check below dead.
	//
	// Worse than dead. The counting is from the right, which is what
	// makes a prepended entry harmless: index len-trustedHops is
	// whatever the outermost trusted proxy recorded, however much the
	// caller put in front of it. Truncating the slice destroys that —
	// a caller who sends 84 entries ahead of 16 real proxies turns
	// len-16 from "the address the outermost proxy saw" into index 0,
	// which is theirs. The seventeenth element is the signal to stop,
	// so it has to survive the split.
	parts := strings.SplitN(xff, ",", maxXFEntries+1)
	if len(parts) > maxXFEntries {
		return addrFromRemoteAddr(r)
	}

	// From the right: the entry trustedHops back is the one the
	// outermost proxy we control wrote. Everything to its left came
	// from whoever was talking to that proxy, and none of it is ours
	idx := len(parts) - trustedHops
	if idx < 0 {
		// Fewer entries than proxies we expect: either a
		// misconfiguration or an attempt to make us read further left
		// than we should.
		return addrFromRemoteAddr(r)
	}
	a, err := netip.ParseAddr(strings.TrimSpace(parts[idx]))
	if err != nil {
		return addrFromRemoteAddr(r)
	}
	return a, nil
}

func addrFromRemoteAddr(r *http.Request) (netip.Addr, error) {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	return netip.ParseAddr(host)
}
