package domain

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"strconv"
	"time"

	"github.com/fotini85/tokenguard/internal/apperr"
	token "github.com/fotini85/tokenguard/internal/token"
)

// TokenSigner is the part of token.Codec this package uses.
//
// Declared here rather than importing the concrete type: the service
// signs and never verifies, so this is the whole of what it needs.
type TokenSigner interface {
	Sign(cl token.Claims) (string, error)
}

// AuthService issues, refreshes and revokes sessions.
//
// Reads go through the plain repositories; every write goes through the
// unit of work. The split is deliberate: checking a password costs
// around 250ms of CPU, and doing that inside a transaction would hold a
// connection for the whole of it, stalling every other writer behind
// work that has nothing to do with the database.
//
// The rule is worth keeping even where a write is single, so nobody has
// to work out which repository is transactional.
type AuthService struct {
	uow UnitOfWork // every write

	users    UserRepo    // reads only
	sessions SessionRepo // reads only

	hasher Hasher
	signer TokenSigner

	accessTTL  time.Duration
	refreshTTL time.Duration

	// onRevoke is called after a revocation commits, so the middleware
	// can stop honouring the session before its access token expires.
	//
	// After, never inside: the bloom filter it feeds cannot delete, so
	// a rollback would leave it flagging a session that is in fact
	// still valid, forcing a database lookup on that user's every
	// request until the filter rotates.
	//
	// A callback rather than a direct call, so this package never
	// imports the filter. main supplies it.
	onRevoke func(sessionID string, at time.Time)

	now func() time.Time
}

type Config struct {
	UoW        UnitOfWork
	Users      UserRepo
	Sessions   SessionRepo
	Hasher     Hasher
	Signer     TokenSigner
	AccessTTL  time.Duration
	RefreshTTL time.Duration
	OnRevoke   func(sessionID string, at time.Time)
	Now        func() time.Time
}

func NewAuthService(cfg Config) *AuthService {
	if cfg.UoW == nil || cfg.Users == nil || cfg.Sessions == nil {
		panic("domain: UoW, Users and Sessions are required")
	}
	if cfg.Hasher == nil || cfg.Signer == nil {
		panic("domain: Hasher and Signer are required")
	}
	if cfg.AccessTTL <= 0 {
		cfg.AccessTTL = 10 * time.Minute
	}
	if cfg.RefreshTTL <= 0 {
		cfg.RefreshTTL = 30 * 24 * time.Hour
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.OnRevoke == nil {
		cfg.OnRevoke = func(string, time.Time) {}
	}
	return &AuthService{
		uow:        cfg.UoW,
		users:      cfg.Users,
		sessions:   cfg.Sessions,
		hasher:     cfg.Hasher,
		signer:     cfg.Signer,
		accessTTL:  cfg.AccessTTL,
		refreshTTL: cfg.RefreshTTL,
		onRevoke:   cfg.OnRevoke,
		now:        cfg.Now,
	}
}

// Tokens is what a caller gets after signing in or refreshing.
//
// A named struct rather than three return values: two strings side by
// side are easy to pass in the wrong order, and t.Access cannot be
// mistaken for t.Refresh.
type Tokens struct {
	Access    string
	Refresh   string
	ExpiresAt time.Time
}

// Login checks credentials and starts a session, ending any previous
// one for the same account.
//
// The lookup and the password check happen outside any transaction. A
// transaction opened before the hash would sit idle for a quarter of a
// second per sign-in while holding a connection; it opens only once
// there is something to write.
func (s *AuthService) Login(ctx context.Context, email, password string) (Tokens, error) {
	const op = "domain.Login"

	u, err := s.users.ByEmail(ctx, email)
	if err != nil {
		// A database failure is not a failed login. Flattening it in with
		// the rest would answer 401 while the database is down, sending
		// everyone to reset a password that was never the problem.
		if apperr.KindOf(err) != apperr.KindNotFound {
			return Tokens{}, apperr.E(op, apperr.KindInternal, err)
		}

		// From here on the address is simply unknown, and the caller must
		// not be able to tell that apart from a wrong password.
		//
		// Two things have to match for that, not one. The time: returning
		// without hashing makes this path measurably faster, so hash a
		// throwaway. And the answer: the Kind decides the status code, so
		// it is the same Kind the wrong-password branch below returns.
		// KindNotFound here would mean 404 against the 401 of a wrong
		// password, and one request per address would map every account
		// on the service.
		//
		// The original error is still wrapped, so the logs can tell the
		// two apart even though the response cannot.

		// Hash rather than compare against a stored dummy. Both run 2^cost
		// rounds of bcrypt, so either spends the right amount of CPU, but
		// Hash takes its cost from the configured hasher. A dummy is a
		// constant with a cost baked into it: raise the hasher to 12 and a
		// cost-10 dummy leaves this path four times faster than the one
		// below, which is the hole this line exists to close.
		//
		// Matched, not identical. bcrypt stores its cost inside every
		// hash, so an account created under an older, cheaper setting
		// still verifies at that cost until its next sign-in rehashes it.
		// Timing is the weaker of the two defences for exactly this
		// reason; the status code above is the one that holds.
		_, _ = s.hasher.Hash(password)
		return Tokens{}, apperr.E(op, apperr.KindBadSignature, err)
	}

	if err := s.hasher.Compare(u.PasswordHash, password); err != nil {
		return Tokens{}, apperr.E(op, apperr.KindBadSignature, err)
	}

	// Only now is there a write to do.
	return s.issue(ctx, op, u.ID, "")
}

// Refresh exchanges a refresh token for a new pair.
//
// The lookup is a read and stays outside the transaction; the rotation
// that follows is two writes and does not.
func (s *AuthService) Refresh(ctx context.Context, refresh string) (Tokens, error) {
	const op = "domain.Refresh"

	now := s.now()

	old, err := s.sessions.ByRefreshHash(ctx, hashToken(refresh))
	if err != nil {
		if apperr.KindOf(err) != apperr.KindNotFound {
			return Tokens{}, apperr.E(op, apperr.KindInternal, err)
		}
		// A token nobody ever held and a token that has been revoked get
		// the same answer. 404 here would confirm that a guessed token
		// once existed, which is a bit of information per guess, and the
		// guesses are free.
		return Tokens{}, apperr.E(op, apperr.KindRevoked, err)
	}
	if !old.Live(now) {
		return Tokens{}, apperr.E(op, apperr.KindRevoked, nil)
	}

	return s.issue(ctx, op, old.UserID, old.ID)
}

// Revoke ends a session.
//
// One write, so a transaction buys nothing here in itself. It goes
// through the unit of work regardless, because "every write goes
// through the unit of work" is a rule worth applying without thinking.
func (s *AuthService) Revoke(ctx context.Context, sessionID string) error {
	const op = "domain.Revoke"

	now := s.now()

	err := s.uow.Do(ctx, func(tx Tx) error {
		return tx.Sessions().Revoke(ctx, sessionID, now)
	})
	if err != nil {
		return apperr.E(op, apperr.KindInternal, err)
	}

	// Committed. Only now may the filter hear about it.
	s.onRevoke(sessionID, now)
	return nil
}

// issue ends what came before and creates a fresh session, both in one
// transaction.
//
// replaceID names a single session to end, for a rotation; empty means
// end all of the user's sessions, for a sign-in.
//
// The two writes have to land together. Fail after the first and the
// user is left with no valid refresh token, locked out until they sign
// in again; fail after the second and two sessions are live at once,
// which is what one-session-per-user exists to prevent. This is the
// case the unit of work is here for.
//
// Both ids are generated before the transaction opens, so no time is
// spent inside it on anything but the writes.
func (s *AuthService) issue(ctx context.Context, op string, userID int64, replaceID string) (Tokens, error) {
	now := s.now()

	sid, err := randomID()
	if err != nil {
		return Tokens{}, apperr.E(op, apperr.KindInternal, err)
	}
	refresh, err := randomID()
	if err != nil {
		return Tokens{}, apperr.E(op, apperr.KindInternal, err)
	}

	err = s.uow.Do(ctx, func(tx Tx) error {
		// tx.Sessions(), never s.sessions: the latter writes through
		// the pool, auto-commits, and would survive a rollback.

		if replaceID != "" {

			// This is also the check, not just the write.
			//
			// The session was read and found live a moment ago, outside
			// this transaction. Revoke matches on revoked_at IS NULL, so
			// if it reports nothing changed, something ended the session
			// in between — a sign-out everywhere, most likely, or the
			// same refresh token arriving twice at once.
			//
			// Carrying on would insert a fresh live session on the
			// strength of a refresh token that had already been
			// cancelled, which is the one thing signing out everywhere
			// is supposed to prevent. Returning the error rolls the
			// whole rotation back.
			if err := tx.Sessions().Revoke(ctx, replaceID, now); err != nil {
				return err
			}
		} else {
			if err := tx.Sessions().RevokeAllForUser(ctx, userID, now); err != nil {
				return err
			}
		}
		return tx.Sessions().Insert(ctx, &Session{
			ID:          sid,
			UserID:      userID,
			RefreshHash: hashToken(refresh),
			IssuedAt:    now,
			ExpiresAt:   now.Add(s.refreshTTL),
		})
	})
	if err != nil {
		// A rotation that found nothing live to replace is not a server
		// fault — the refresh token simply is not good any more, which
		// is the same answer as presenting a revoked one.
		if apperr.KindOf(err) == apperr.KindNotFound {
			return Tokens{}, apperr.E(op, apperr.KindRevoked, err)
		}
		return Tokens{}, apperr.E(op, apperr.KindInternal, err)
	}

	// Committed.
	if replaceID != "" {
		s.onRevoke(replaceID, now)
	}

	expires := now.Add(s.accessTTL)
	access, err := s.signer.Sign(token.Claims{
		Kind: token.KindAccess,
		// A string, because the token package has no opinion on how
		// an application identifies people. The conversion happens
		// here, at the boundary.
		UserID:    strconv.FormatInt(userID, 10),
		SessionID: sid,
		IssuedAt:  now,
		ExpiresAt: expires,
	})
	if err != nil {
		// The session is in the database while the caller has no token
		// for it. Harmless: it expires on its own, and the next sign-in
		// revokes it.
		return Tokens{}, apperr.E(op, apperr.KindInternal, err)
	}

	return Tokens{Access: access, Refresh: refresh, ExpiresAt: expires}, nil
}

// randomID returns 128 bits of entropy, url-safe.
//
// crypto/rand, never math/rand: the latter is predictable, and someone
// who sees a handful of ids could work out the ones that follow.
func randomID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// hashToken is what goes into the database in place of the token, for
// the same reason passwords are hashed: reading the table should not
// leave someone able to sign in as anyone.
//
// Plain SHA-256 rather than bcrypt. A refresh token is 128 random bits,
// so there is no dictionary to run against it and nothing a slow hash
// would buy. It also has to be deterministic to be searchable — bcrypt
// salts each call, so WHERE refresh_hash = $1 could never match.
func hashToken(t string) []byte {
	h := sha256.Sum256([]byte(t))
	return h[:]
}
