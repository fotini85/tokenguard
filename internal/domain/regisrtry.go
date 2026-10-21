package domain

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/fotini85/tokenguard/internal/apperr"
	//"golang.org/x/text/unicode/norm"
)

type Registry struct {
	uow    UnitOfWork
	hasher Hasher
	now    func() time.Time
}

func NewRegistry(uow UnitOfWork, hasher Hasher, now func() time.Time) *Registry {
	if uow == nil || hasher == nil {
		panic("domain: UoW and Hasher are required")
	}
	if now == nil {
		now = time.Now
	}
	return &Registry{uow: uow, hasher: hasher, now: now}
}

func (r *Registry) Register(ctx context.Context, email, password string) (int64, error) {
	const op = "domain.Register"

	email = normaliseEmail(email)
	if err := validateEmail(email); err != nil {
		return 0, apperr.E(op, apperr.KindMalformed, err)
	}
	if err := validatePassword(password); err != nil {
		return 0, apperr.E(op, apperr.KindMalformed, err)
	}

	hash, err := r.hasher.Hash(password)
	if err != nil {
		return 0, apperr.E(op, apperr.KindInternal, err)
	}

	var id int64
	err = r.uow.Do(ctx, func(tx Tx) error {
		var err error
		id, err = tx.Users().Insert(ctx, &User{
			Email:        email,
			PasswordHash: hash,
			CreatedAt:    r.now(),
		})
		return err
	})

	if err != nil {
		// No SELECT before this insert, on purpose. Checking whether
		// the address exists and then inserting is a race: two
		// registrations arriving together both find nothing and both
		// proceed. The unique index on lower(email) is the only real
		// guarantee, so the duplicate is caught here
		if apperr.KindOf(err) == apperr.KindConflict {
			return 0, apperr.E(op, apperr.KindConflict, err)
		}
		return 0, apperr.E(op, apperr.KindInternal, err)
	}

	return id, nil
}

func normaliseEmail(s string) string {
	// NFC first: the same address can arrive as different bytes
	// depending on the device — macOS hands back decomposed forms
	// where Linux and Windows compose them. Without this, josé@x.com
	// from a Mac and from a phone are two accounts, and the unique
	// index cannot tell they are the same.
	return strings.ToLower(strings.TrimSpace(s))
}

func validateEmail(s string) error {
	if len(s) < 3 || len(s) > 254 {
		return errors.New("email length out of range")
	}
	at := strings.IndexByte(s, '@')
	if at < 1 || at == len(s)-1 {
		return errors.New("email needs a local part and a domain")
	}

	if strings.Contains(s[at+1:], "@") {
		return errors.New("email contains more than one @")
	}

	for i := 0; i < len(s); i++ {
		if s[i] > 127 {
			return errors.New("email must be ASCII")
		}
	}
	return nil
}

func validatePassword(s string) error {
	if len(s) < 12 {
		return errors.New("password must be at least 12 characters")
	}
	if len(s) > 72 {
		return errors.New("password must be at most 72 bytes")
	}
	return nil
}
