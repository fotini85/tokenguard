package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/fotini85/tokenguard/internal/apperr"
	"github.com/fotini85/tokenguard/internal/domain"
)

var _ domain.SessionRepo = (*sessionRepo)(nil)

// q is either the pool or a transaction, decided by whoever built this.
// The SQL is identical either way — that is the whole point of the
// querier interface.
type sessionRepo struct {
	q querier
}

func (r *sessionRepo) ByRefreshHash(ctx context.Context, hash []byte) (*domain.Session, error) {
	const op = "postgres.ByRefreshHash"

	const query = `
	    SELECT id, user_id, refresh_hash, issued_at, expires_at, revoked_at
		FROM sessions
		WHERE refresh_hash = $1`

	var s domain.Session
	err := r.q.QueryRow(ctx, query, hash).Scan(
		&s.ID, &s.UserID, &s.RefreshHash,
		&s.IssuedAt, &s.ExpiresAt, &s.RevokedAt)

	if errors.Is(err, pgx.ErrNoRows) {
		return nil, apperr.E(op, apperr.KindNotFound, err)
	}
	if err != nil {
		return nil, apperr.E(op, apperr.KindInternal, err)
	}
	return &s, nil
}

func (r *sessionRepo) Insert(ctx context.Context, s *domain.Session) error {
	const op = "postgres.InsertSession"

	const q = `
		INSERT INTO sessions (id, user_id, refresh_hash, issued_at, expires_at)
		VALUES ($1, $2, $3, $4, $5)`

	_, err := r.q.Exec(ctx, q,
		s.ID, s.UserID, s.RefreshHash, s.IssuedAt, s.ExpiresAt)
	if err != nil {
		if isUniqueViolation(err) {
			return apperr.E(op, apperr.KindConflict, err)
		}
		return apperr.E(op, apperr.KindInternal, err)
	}
	return nil
}

// IsRevoked is what the middleware falls back to when the bloom filter
// reports a maybe.
func (r *sessionRepo) IsRevoked(ctx context.Context, id string) (bool, error) {
	const op = "postgres.IsRevoked"

	const query = `SELECT revoked_at IS NOT NULL FROM sessions WHERE id=$1`

	var revoked bool
	err := r.q.QueryRow(ctx, query, id).Scan(&revoked)

	if errors.Is(err, pgx.ErrNoRows) {
		return true, nil
	}
	if err != nil {
		return false, apperr.E(op, apperr.KindInternal, err)
	}
	return revoked, nil
}

// RevokeAllForUser ends every live session for an account, which is
// what a fresh sign-in does under one-session-per-user, and returns the
// ids it ended so the caller can name them to the denylist.
//
// RETURNING in the statement that writes, so one scan does both and the
// ids can never describe rows the write did not touch. No row count
// check, unlike Revoke: this is a sweep, and a first sign-in having
// nothing to revoke would otherwise mean no account could be used
// twice.
func (r *sessionRepo) RevokeAllForUser(ctx context.Context, userID int64, at time.Time) ([]string, error) {
	const op = "postgres.RevokeAllForUser"

	const query = `
		UPDATE sessions
		SET revoked_at = $2
		WHERE user_id = $1 AND revoked_at IS NULL
		RETURNING id`

	rows, err := r.q.Query(ctx, query, userID, at)
	if err != nil {
		return nil, apperr.E(op, apperr.KindInternal, err)
	}
	// Rows hold the connection until they are closed, and the caller
	// writes again on this same transaction immediately after. Without
	// this the next statement fails with "conn busy".
	defer rows.Close()

	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, apperr.E(op, apperr.KindInternal, err)
		}
		ids = append(ids, id)
	}

	// Next reports false both at the end of the results and on failure,
	// so without this a connection dropped halfway through reads as a
	// short list and the sessions it did not name stay honoured.
	if err := rows.Err(); err != nil {
		return nil, apperr.E(op, apperr.KindInternal, err)
	}

	return ids, nil
}

// revoked_at IS NULL keeps the original revocation time: without it a
// second revoke would overwrite the first, and the history of when a
// session actually ended would be lost.
//
// It also makes the row count meaningful. No row matched means the
// session is gone or was already revoked, and the caller is the only
// one who can say whether that matters — a sign-out shrugs at it, a
// refresh rotation must not.
func (r *sessionRepo) Revoke(ctx context.Context, id string, at time.Time) error {
	const op = "postgres.Revoke"

	const query = `
		UPDATE sessions
		SET revoked_at = $2
		WHERE id = $1 AND revoked_at IS NULL`

	tag, err := r.q.Exec(ctx, query, id, at)
	if err != nil {
		return apperr.E(op, apperr.KindInternal, err)
	}
	if tag.RowsAffected() == 0 {
		return apperr.E(op, apperr.KindNotFound, nil)
	}
	return nil
}
