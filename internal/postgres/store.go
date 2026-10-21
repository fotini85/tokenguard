package postgres

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/fotini85/tokenguard/internal/apperr"
	"github.com/fotini85/tokenguard/internal/domain"
)

type Store struct {
	pool *pgxpool.Pool
}

func New(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}

}

func (s *Store) Users() domain.UserRepo       { return &userRepo{q: s.pool} }
func (s *Store) Sessions() domain.SessionRepo { return &sessionRepo{q: s.pool} }

type txView struct{ tx pgx.Tx }

func (t *txView) Users() domain.UserRepo       { return &userRepo{q: t.tx} }
func (t *txView) Sessions() domain.SessionRepo { return &sessionRepo{q: t.tx} }

func (s *Store) Do(ctx context.Context, fn func(domain.Tx) error) error {
	const op = "postgres.Transaction"
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return apperr.E(op, apperr.KindInternal, err)
	}
	defer tx.Rollback(ctx)
	if err := fn(&txView{tx: tx}); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return apperr.E(op, apperr.KindInternal, err)
	}
	return nil

}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}
