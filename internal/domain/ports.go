package domain

import (
	"context"
	"time"
)

type User struct {
	ID    int64
	Email string

	PasswordHash []byte

	CreatedAt time.Time
}

type Session struct {
	ID     string
	UserID int64

	RefreshHash []byte

	IssuedAt  time.Time
	ExpiresAt time.Time

	// RevokedAt is nil while the session is live.
	//
	// A pointer because time.Time has no empty value: its zero is the
	// first of January, year 1, which is a real date rather than an
	// absence. nil and non-nil are two clear states, and they map
	// straight onto NULL in the database.
	RevokedAt *time.Time
}

func (s *Session) Live(now time.Time) bool {
	return s.RevokedAt == nil && now.Before(s.ExpiresAt)
}

type UserRepo interface {
	ByEmail(ctx context.Context, email string) (*User, error)

	Insert(ctx context.Context, u *User) (int64, error)
}

type SessionRepo interface {
	ByRefreshHash(ctx context.Context, hash []byte) (*Session, error)
	Insert(ctx context.Context, s *Session) error
	Revoke(ctx context.Context, id string, at time.Time) error
	RevokeAllForUser(ctx context.Context, userID int64, at time.Time) error
	IsRevoked(ctx context.Context, id string) (bool, error)
}

type UnitOfWork interface {
	Do(ctx context.Context, fn func(Tx) error) error
}

type Tx interface {
	Users() UserRepo
	Sessions() SessionRepo
}

type Hasher interface {
	Hash(password string) ([]byte, error)
	Compare(hash []byte, password string) error
}
