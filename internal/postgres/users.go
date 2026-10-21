package postgres

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	"github.com/fotini85/tokenguard/internal/apperr"
	"github.com/fotini85/tokenguard/internal/domain"
)

type userRepo struct {
	q querier
}

func (r *userRepo) ByEmail(ctx context.Context, email string) (*domain.User, error) {
	const op = "postgres.ByEmail"
	const q = `
		SELECT id, email, password_hash, created_at
		FROM users
		WHERE lower(email) = lower($1)`

	var u domain.User
	err := r.q.QueryRow(ctx, q, email).
		Scan(&u.ID, &u.Email, &u.PasswordHash, &u.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, apperr.E(op, apperr.KindNotFound, err)
	}
	if err != nil {
		return nil, apperr.E(op, apperr.KindInternal, err)
	}
	return &u, nil

}

func (r *userRepo) Insert(ctx context.Context, u *domain.User) (int64, error) {
	const op = "postgres.InsertUser"

	const q = `
		 INSERT INTO users (email, password_hash, created_at)
		 VALUES ($1, $2, $3)
		 RETURNING id`

	var id int64
	err := r.q.QueryRow(ctx, q, u.Email, u.PasswordHash, u.CreatedAt).
		Scan(&id)
	if err != nil {
		if isUniqueViolation(err) {

			return 0, apperr.E(op, apperr.KindConflict, err)
		}
		return 0, apperr.E(op, apperr.KindInternal, err)
	}
	return id, nil
}
