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
	    SELECT id, user_id, refresg_hash, issued_at, expires_at, revoke_at
		from sessions
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
// what a fresh sign-in does under one-session-per-user.
func (r *sessionRepo) RevokeAllForUser(ctx context.Context, userID int64, at time.Time) error {
	const op = "postgres.RevokeAllForUser"

	const query = `
		UPDATE sessions
		SET revoked_at = $2
		WHERE user_id = $1 AND revoked_at IS NULL`

	if _, err := r.q.Exec(ctx, query, userID, at); err != nil {
		return apperr.E(op, apperr.KindInternal, err)
	}
	return nil
}

// revoked_at IS NULL: used here to keep sessions history avoiding overwriring older sessions
func (r *sessionRepo) Revoke(ctx context.Context, id string, at time.Time) error {
	const op = "postgres.Revoke"

	const query = `
		UPDATE sessions
		SET revoked_at = $2
		WHERE id = $1 AND revoked_at IS NULL`

	if _, err := r.q.Exec(ctx, query, id, at); err != nil {
		return apperr.E(op, apperr.KindInternal, err)
	}
	return nil
}
