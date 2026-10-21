// Command demo wires the pieces together and serves them.
//
// Everything in internal/ is written not to know what it is plugged
// into. This is the one place that does: it reads configuration,
// constructs each piece, and connects them. No logic lives here.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/fotini85/tokenguard/internal/authmw"
	"github.com/fotini85/tokenguard/internal/bloom"
	"github.com/fotini85/tokenguard/internal/bucket"
	"github.com/fotini85/tokenguard/internal/crypto"
	"github.com/fotini85/tokenguard/internal/domain"
	"github.com/fotini85/tokenguard/internal/httpapi"
	"github.com/fotini85/tokenguard/internal/httpmw"
	"github.com/fotini85/tokenguard/internal/limiter"
	"github.com/fotini85/tokenguard/internal/postgres"
	"github.com/fotini85/tokenguard/internal/token"
)

const (
	accessTTL  = 10 * time.Minute
	refreshTTL = 30 * 24 * time.Hour

	// The denylist window matches the access TTL on purpose: a
	// revocation older than that is pointless, because the token it
	// refers to has expired on its own and the codec rejects it before
	// the filter is ever consulted.
	denylistWindow = accessTTL
)

func main() {
	// run returns an error instead of calling os.Exit, so every defer
	// above it still gets to run. os.Exit skips them.
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "fatal:", err)
		os.Exit(1)
	}
}

func run() error {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	ctx := context.Background()
	now := time.Now

	// --- database ---------------------------------------------------

	dbURL := env("DATABASE_URL", "postgres://postgres:dev@127.0.0.1:5432/tokenguard")

	pool, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		return fmt.Errorf("connecting to postgres: %w", err)
	}
	defer pool.Close()

	// New does not connect; it only parses. Ping here so a wrong URL
	// fails at startup rather than on the first request.
	pingCtx, cancelPing := context.WithTimeout(ctx, 5*time.Second)
	defer cancelPing()
	if err := pool.Ping(pingCtx); err != nil {
		return fmt.Errorf("pinging postgres: %w", err)
	}

	store := postgres.New(pool)

	// --- signing key ------------------------------------------------

	key, err := signingKey()
	if err != nil {
		return err
	}
	codec := token.NewCodec(key, now)

	// --- revocation denylist ----------------------------------------

	denylist := bloom.NewRotating(10_000, 0.001, denylistWindow, now())

	// --- domain -----------------------------------------------------

	hasher := crypto.NewBcrypt(12)

	auth := domain.NewAuthService(domain.Config{
		UoW:        store,
		Users:      store.Users(),
		Sessions:   store.Sessions(),
		Hasher:     hasher,
		Signer:     codec,
		AccessTTL:  accessTTL,
		RefreshTTL: refreshTTL,
		Now:        now,

		// This is where the domain reaches the bloom filter without
		// importing it. The service calls onRevoke after a revocation
		// commits; what happens then is decided here.
		OnRevoke: func(sid string, at time.Time) {
			denylist.Add(sid, at)
		},
	})

	registry := domain.NewRegistry(store, hasher, now)

	// --- rate limiting ----------------------------------------------

	// Two limiters, not one. Anonymous callers are identified loosely —
	// everyone behind one NAT looks the same — so their limit is tight
	// and their key space is unbounded, which is why MaxKeys exists.
	// Signed-in callers are identified exactly, so their limit is
	// generous and their key space is bounded by the number of accounts.
	ipLimiter := limiter.New(limiter.Config{
		Policy: bucket.Policy{
			AllowedRequests: 30,
			Window:          time.Minute,
			MaxAtOnce:       10,
			MaxCost:         10,
		},
		MaxKeys: 65_536,
	})

	userLimiter := limiter.New(limiter.Config{
		Policy: bucket.Policy{
			AllowedRequests: 300,
			Window:          time.Minute,
			MaxAtOnce:       60,
			MaxCost:         10,
		},
		MaxKeys: 65_536,
	})

	mw := authmw.New(authmw.Config{
		Codec:     codec,
		IPLimit:   ipLimiter,
		UserLimit: userLimiter,
		Denylist:  denylist,
		Revoked:   store.Sessions(),
		Now:       now,

		// Zero unless a proxy sits in front and nothing else can reach
		// this server. Trusting X-Forwarded-For on an open port would
		// let a caller mint a new identity per request.
		TrustedProxyHops: envInt("TRUSTED_PROXY_HOPS", 0),

		Cost: requestCost,
	})

	// --- routing ----------------------------------------------------

	api := httpapi.New(auth, registry)

	mux := http.NewServeMux()
	mux.Handle("/auth/", mw.Handler(api.Routes()))
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Recover outermost: it can only catch panics from what it wraps.
	handler := httpmw.Recover(log)(mux)

	// --- server -----------------------------------------------------

	addr := env("ADDR", "127.0.0.1:8080")

	srv := &http.Server{
		Addr:    addr,
		Handler: handler,

		// Without these, a client that opens a connection and sends
		// nothing holds a goroutine and a file descriptor for as long
		// as it likes. A few thousand of those and the server is out of
		// both, having served nobody.
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,

		// The default is 1MB of headers per request. These endpoints
		// need a fraction of that.
		MaxHeaderBytes: 8 << 10,
	}

	// ListenAndServe blocks, so it runs on its own goroutine and
	// reports back through a channel. Buffered by one so the send
	// never blocks if nobody is left to receive it.
	serveErr := make(chan error, 1)
	go func() {
		log.Info("listening", "addr", addr)
		serveErr <- srv.ListenAndServe()
	}()

	// Buffered by one as well: signal.Notify never blocks, and an
	// unbuffered channel here would drop the signal.
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	select {
	case err := <-serveErr:
		// ErrServerClosed is what Shutdown causes, so it only means a
		// real failure when it arrives before we asked to stop.
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("serving: %w", err)
		}
		return nil

	case sig := <-stop:
		log.Info("shutting down", "signal", sig.String())
	}

	// Shutdown stops accepting new connections and waits for the ones
	// in flight. The timeout bounds that wait: a request that will not
	// finish should not keep the process alive indefinitely.
	shutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := srv.Shutdown(shutCtx); err != nil {
		return fmt.Errorf("shutting down: %w", err)
	}

	log.Info("stopped")
	return nil
}

// requestCost says how much of a caller's allowance a request spends.
//
// Not every request costs the same. Login runs bcrypt and burns about
// 250ms of CPU; a health check costs nothing. Charging both a flat one
// would let the expensive ones through at the same rate as the cheap
// ones, which is exactly backwards.
func requestCost(r *http.Request) float64 {
	switch r.URL.Path {
	case "/auth/login", "/auth/register":
		return 10
	case "/auth/refresh":
		return 3
	default:
		return 1
	}
}

// signingKey reads the HMAC key from the environment, or generates one.
//
// A generated key is fine for a demo and wrong for anything else: it
// changes on every restart, so every token issued before the restart
// stops verifying and everyone is signed out.
func signingKey() ([]byte, error) {
	if s := os.Getenv("SIGNING_KEY"); s != "" {
		key, err := hex.DecodeString(s)
		if err != nil {
			return nil, fmt.Errorf("SIGNING_KEY must be hex: %w", err)
		}
		if len(key) < 32 {
			return nil, errors.New("SIGNING_KEY must be at least 32 bytes")
		}
		return key, nil
	}

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generating signing key: %w", err)
	}
	fmt.Fprintf(os.Stderr,
		"warning: no SIGNING_KEY set, generated one. Every restart "+
			"invalidates all tokens.\n  SIGNING_KEY=%s\n", hex.EncodeToString(key))
	return key, nil
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envInt(key string, fallback int) int {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return fallback
	}
	return n
}
