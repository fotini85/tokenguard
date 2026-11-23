package domain_test

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/fotini85/tokenguard/internal/apperr"
	"github.com/fotini85/tokenguard/internal/domain"
	"github.com/fotini85/tokenguard/internal/token"
)

// The fakes below implement only what the path under test actually
// reaches. Anything else panics, which is louder than returning a zero
// value and letting the test pass for the wrong reason.
//
// This is what the interfaces in ports.go were for. Nothing here touches
// Postgres, so the whole file runs in microseconds.

type fakeUsers struct {
	user *domain.User
	err  error
}

func (f *fakeUsers) ByEmail(context.Context, string) (*domain.User, error) {
	return f.user, f.err
}

func (f *fakeUsers) Insert(context.Context, *domain.User) (int64, error) {
	panic("Insert must not be reached: Login never creates an account")
}

// fakeHasher counts work as well as answering. Whether the expensive
// operation ran is the point of the timing test below, not an incidental
// detail.
//
// Hash and Compare share one counter because they cost the same: both
// run 2^cost rounds of bcrypt. Which of the two a path happens to call
// does not matter, only that a path calls one of them.
type fakeHasher struct {
	err  error
	work int
}

func (f *fakeHasher) Hash(string) ([]byte, error) {
	f.work++
	return []byte("$2a$12$fake"), nil
}

func (f *fakeHasher) Compare([]byte, string) error {
	f.work++
	return f.err
}

type panicSessions struct{}

func (panicSessions) ByRefreshHash(context.Context, []byte) (*domain.Session, error) {
	panic("unused")
}
func (panicSessions) Insert(context.Context, *domain.Session) error   { panic("unused") }
func (panicSessions) Revoke(context.Context, string, time.Time) error { panic("unused") }
func (panicSessions) RevokeAllForUser(context.Context, int64, time.Time) ([]string, error) {
	panic("unused")
}
func (panicSessions) IsRevoked(context.Context, string) (bool, error) { panic("unused") }
func (panicSessions) RevokedSince(context.Context, time.Time) ([]string, error) {
	panic("unused")
}
func (s *recordingSessions) RevokedSince(context.Context, time.Time) ([]string, error) {
	panic("unused: warming happens in main, not in a service")
}

type panicUoW struct{}

func (panicUoW) Do(context.Context, func(domain.Tx) error) error {
	panic("Do must not be reached: a failed login has nothing to write")
}

type panicSigner struct{}

func (panicSigner) Sign(token.Claims) (string, error) {
	panic("Sign must not be reached: a failed login issues no token")
}

func newService(users domain.UserRepo, hasher domain.Hasher) *domain.AuthService {
	return domain.NewAuthService(domain.Config{
		UoW:      panicUoW{},
		Users:    users,
		Sessions: panicSessions{},
		Hasher:   hasher,
		Signer:   panicSigner{},
	})
}

// A caller must not be able to work out whether an address has an
// account. Two things decide that, and both are checked here.
//
// The status code: if an unknown address answers 404 while a wrong
// password answers 401, one request per address maps every account on
// the service.
//
// The time: bcrypt is the only slow part of this endpoint, so returning
// without running it makes the unknown-address path measurably shorter
// even when both answer 401.
func TestLoginDoesNotRevealWhetherAccountExists(t *testing.T) {
	const password = "correct horse battery"

	cases := []struct {
		name   string
		users  *fakeUsers
		hasher *fakeHasher
	}{
		{
			name:   "unknown address",
			users:  &fakeUsers{err: apperr.E("fake", apperr.KindNotFound, nil)},
			hasher: &fakeHasher{err: errors.New("hash mismatch")},
		},
		{
			name:   "known address, wrong password",
			users:  &fakeUsers{user: &domain.User{ID: 1, Email: "a@b.c"}},
			hasher: &fakeHasher{err: errors.New("hash mismatch")},
		},
	}

	var statuses []int

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			svc := newService(c.users, c.hasher)

			_, err := svc.Login(context.Background(), "a@b.c", password)
			if err == nil {
				t.Fatal("Login succeeded, want failure")
			}

			if c.hasher.work != 1 {
				t.Errorf("hasher did %d units of work, want 1: "+
					"skipping bcrypt makes this path shorter than the other",
					c.hasher.work)
			}

			status, _ := apperr.HTTPStatus(err)
			statuses = append(statuses, status)
		})
	}

	if len(statuses) == 2 && statuses[0] != statuses[1] {
		t.Errorf("unknown address answered %d, wrong password answered %d: "+
			"the difference enumerates accounts", statuses[0], statuses[1])
	}
}

// Flattening every lookup failure into 401 would be the wrong fix for
// the test above: while the database is down, every caller would be told
// their password was wrong and sent to reset a credential that was never
// the problem.
func TestLoginReportsDatabaseFailureAsInternal(t *testing.T) {
	users := &fakeUsers{
		err: apperr.E("fake", apperr.KindInternal, errors.New("connection refused")),
	}
	svc := newService(users, &fakeHasher{})

	_, err := svc.Login(context.Background(), "a@b.c", "correct horse battery")
	if err == nil {
		t.Fatal("Login succeeded, want failure")
	}

	if status, _ := apperr.HTTPStatus(err); status != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d: an outage must not look like a wrong password",
			status, http.StatusInternalServerError)
	}
}

// The response says nothing, but the logs still have to. Flattening the
// Kind must not throw away the error underneath it, or an unknown
// address and a wrong password become indistinguishable to us as well.
func TestLoginKeepsTheRealCauseForLogs(t *testing.T) {
	notFound := apperr.E("fake", apperr.KindNotFound, nil)
	svc := newService(&fakeUsers{err: notFound}, &fakeHasher{err: errors.New("mismatch")})

	_, err := svc.Login(context.Background(), "a@b.c", "correct horse battery")
	if !errors.Is(err, notFound) {
		t.Error("the underlying not-found error was dropped")
	}
}

// The fakes above refuse to be used; these ones work, because a
// rotation has to be allowed to run far enough to be judged.

type recordingSessions struct {
	session   *domain.Session // what ByRefreshHash finds
	revokeErr error           // what Revoke reports

	// liveForUser is what RevokeAllForUser finds and hands back: the
	// account's other sessions, on other devices.
	liveForUser []string

	inserted []*domain.Session
	revoked  []string
}

func (s *recordingSessions) ByRefreshHash(context.Context, []byte) (*domain.Session, error) {
	if s.session == nil {
		return nil, apperr.E("fake", apperr.KindNotFound, nil)
	}
	return s.session, nil
}

func (s *recordingSessions) Insert(_ context.Context, ses *domain.Session) error {
	s.inserted = append(s.inserted, ses)
	return nil
}

func (s *recordingSessions) Revoke(_ context.Context, id string, _ time.Time) error {
	s.revoked = append(s.revoked, id)
	return s.revokeErr
}

func (s *recordingSessions) RevokeAllForUser(context.Context, int64, time.Time) ([]string, error) {
	s.revoked = append(s.revoked, s.liveForUser...)
	return s.liveForUser, nil
}

func (s *recordingSessions) IsRevoked(context.Context, string) (bool, error) {
	panic("unused")
}

// fakeUoW runs the callback and nothing else. It does not roll back,
// which is the point: what the tests below check is that the callback
// returned before it ever reached the insert, not that a rollback
// cleaned up afterwards.
type fakeUoW struct{ tx domain.Tx }

func (u fakeUoW) Do(_ context.Context, fn func(domain.Tx) error) error { return fn(u.tx) }

type fakeTx struct{ sessions domain.SessionRepo }

func (t fakeTx) Users() domain.UserRepo       { panic("unused") }
func (t fakeTx) Sessions() domain.SessionRepo { return t.sessions }

type fakeSigner struct{}

func (fakeSigner) Sign(token.Claims) (string, error) { return "signed.access.token", nil }

func refreshService(sessions *recordingSessions, now time.Time, onRevoke func(string, time.Time)) *domain.AuthService {
	return domain.NewAuthService(domain.Config{
		UoW:      fakeUoW{tx: fakeTx{sessions: sessions}},
		Users:    &fakeUsers{},
		Sessions: sessions,
		Hasher:   &fakeHasher{},
		Signer:   fakeSigner{},
		OnRevoke: onRevoke,
		Now:      func() time.Time { return now },
	})
}

func liveSession() *domain.Session {
	return &domain.Session{
		ID:        "old-session",
		UserID:    7,
		ExpiresAt: time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
	}
}

func TestRefreshRotatesTheSession(t *testing.T) {
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	sessions := &recordingSessions{session: liveSession()}

	var filtered []string
	svc := refreshService(sessions, now, func(sid string, _ time.Time) {
		filtered = append(filtered, sid)
	})

	tokens, err := svc.Refresh(context.Background(), "a-refresh-token")
	if err != nil {
		t.Fatalf("Refresh() error = %v", err)
	}
	if tokens.Refresh == "" {
		t.Error("no refresh token issued")
	}

	if want := []string{"old-session"}; len(sessions.revoked) != 1 || sessions.revoked[0] != want[0] {
		t.Errorf("revoked %v, want %v", sessions.revoked, want)
	}
	if len(sessions.inserted) != 1 {
		t.Fatalf("inserted %d sessions, want 1", len(sessions.inserted))
	}
	if sessions.inserted[0].ID == "old-session" {
		t.Error("the replacement reuses the old session id")
	}

	// The filter hears about the old session only once the rotation has
	// committed. It cannot delete, so telling it early and then failing
	// would leave it flagging a session that is still perfectly valid.
	if len(filtered) != 1 || filtered[0] != "old-session" {
		t.Errorf("denylist got %v, want [old-session]", filtered)
	}
}

// The session was alive when it was read, and gone by the time the
// transaction wrote. Signing out everywhere, most likely, or the same
// refresh token arriving twice at once.
//
// Revoke matches on revoked_at IS NULL, so it reports that nothing
// changed, and that report is the only thing standing between a
// cancelled refresh token and a brand new live session. Without it the
// holder of a stolen token keeps rotating it forever, and signing out
// everywhere does nothing.
func TestRefreshStopsWhenTheSessionIsRevokedMidRotation(t *testing.T) {
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	sessions := &recordingSessions{
		session:   liveSession(),
		revokeErr: apperr.E("fake", apperr.KindNotFound, nil),
	}

	var filtered []string
	svc := refreshService(sessions, now, func(sid string, _ time.Time) {
		filtered = append(filtered, sid)
	})

	_, err := svc.Refresh(context.Background(), "a-refresh-token")
	if err == nil {
		t.Fatal("Refresh() succeeded on a session revoked mid-rotation")
	}

	if len(sessions.inserted) != 0 {
		t.Errorf("inserted %d sessions, want 0: a cancelled refresh token "+
			"was turned into a live one", len(sessions.inserted))
	}
	if len(filtered) != 0 {
		t.Errorf("denylist got %v, want nothing: no rotation committed", filtered)
	}

	// 401, not 500. The token is not good any more; nothing broke.
	if status, _ := apperr.HTTPStatus(err); status != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", status, http.StatusUnauthorized)
	}
}

// An expired or already-revoked session is caught by the read, before
// any transaction opens. Same answer as the race above, reached a
// cheaper way.
func TestRefreshRejectsADeadSession(t *testing.T) {
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)

	revokedAt := now.Add(-time.Hour)
	dead := liveSession()
	dead.RevokedAt = &revokedAt

	sessions := &recordingSessions{session: dead}
	svc := refreshService(sessions, now, nil)

	_, err := svc.Refresh(context.Background(), "a-refresh-token")
	if err == nil {
		t.Fatal("Refresh() succeeded on a revoked session")
	}
	if len(sessions.revoked)+len(sessions.inserted) != 0 {
		t.Error("a transaction ran for a session that was already dead")
	}
	if status, _ := apperr.HTTPStatus(err); status != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", status, http.StatusUnauthorized)
	}
}

// Signing in ends this account's other sessions, and the denylist has
// to hear about every one of them by name.
//
// Until RevokeAllForUser returned ids there was nothing to name, so the
// loop did not exist and only a rotated session was ever reported. The
// sessions on the other devices were marked revoked in the database and
// went on being honoured for the whole access token TTL, because the
// filter answered "not revoked" and nothing asked the database.
//
// Which made the two ways of ending a session behave in opposite ways:
// pressing sign-out cut a device off at once, while signing in
// elsewhere — the thing someone does when they think an account is
// compromised — left the intruder a full TTL of access.
func TestLoginTellsTheDenylistAboutEverySessionItEnds(t *testing.T) {
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)

	sessions := &recordingSessions{
		liveForUser: []string{"laptop-session", "phone-session"},
	}

	var filtered []string
	svc := domain.NewAuthService(domain.Config{
		UoW:      fakeUoW{tx: fakeTx{sessions: sessions}},
		Users:    &fakeUsers{user: &domain.User{ID: 7, Email: "a@b.c"}},
		Sessions: sessions,
		Hasher:   &fakeHasher{}, // nil error: the password matches
		Signer:   fakeSigner{},
		OnRevoke: func(sid string, _ time.Time) { filtered = append(filtered, sid) },
		Now:      func() time.Time { return now },
	})

	if _, err := svc.Login(context.Background(), "a@b.c", "correct horse battery"); err != nil {
		t.Fatalf("Login() error = %v", err)
	}

	if len(filtered) != 2 {
		t.Fatalf("denylist got %v, want both sessions: an unreported session "+
			"keeps working until its access token expires", filtered)
	}
	for i, want := range sessions.liveForUser {
		if filtered[i] != want {
			t.Errorf("denylist[%d] = %q, want %q", i, filtered[i], want)
		}
	}
}

// A first sign-in revokes nothing, and nothing must be reported. A
// bloom filter cannot delete, so a session id invented here would cost
// that user a database lookup on every request until the window turns.
func TestLoginTellsTheDenylistNothingWhenNothingWasLive(t *testing.T) {
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	sessions := &recordingSessions{} // no other sessions

	var filtered []string
	svc := domain.NewAuthService(domain.Config{
		UoW:      fakeUoW{tx: fakeTx{sessions: sessions}},
		Users:    &fakeUsers{user: &domain.User{ID: 7, Email: "a@b.c"}},
		Sessions: sessions,
		Hasher:   &fakeHasher{},
		Signer:   fakeSigner{},
		OnRevoke: func(sid string, _ time.Time) { filtered = append(filtered, sid) },
		Now:      func() time.Time { return now },
	})

	if _, err := svc.Login(context.Background(), "a@b.c", "correct horse battery"); err != nil {
		t.Fatalf("Login() error = %v", err)
	}
	if len(filtered) != 0 {
		t.Errorf("denylist got %v, want nothing", filtered)
	}
	if len(sessions.inserted) != 1 {
		t.Errorf("inserted %d sessions, want 1", len(sessions.inserted))
	}
}
