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
	Codec            *token.Codec
	IPLimit          *limiter.Limiter //unbounded
	UserLimit        *limiter.Limiter //strict
	Denylist         *bloom.Rotating
	Revoked          RevocationStore
	TrustProxy       bool //to use or ignore "x-Forwarded-For"
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
			writeErr(w, err)
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
	parts := strings.SplitN(xff, ",", maxXFEntries)
	if len(parts) > maxXFEntries {
		return addrFromRemoteAddr(r)
	}

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

/* στο main todo
srv := &http.Server{
    MaxHeaderBytes: 8 << 10,
}
*/

// authmw — γράφει text/plain
func writeErr(w http.ResponseWriter, err error) {
	status, msg := apperr.HTTPStatus(err)
	if status == http.StatusTooManyRequests {
		w.Header().Set("Retry-After", "1")
	}
	http.Error(w, msg, status)
}
