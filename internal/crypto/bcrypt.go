package crypto

import (
	"golang.org/x/crypto/bcrypt"

	"github.com/fotini85/tokenguard/internal/domain"
)

var _ domain.Hasher = (*Bcrypt)(nil)

type Bcrypt struct {
	cost int
}

func NewBcrypt(cost int) *Bcrypt {
	if cost == 0 {
		cost = bcrypt.DefaultCost
	}
	if cost < bcrypt.MinCost || cost > bcrypt.MaxCost {
		panic("crypto: bcrypt cost out of range")
	}
	return &Bcrypt{cost: cost}
}

func (b *Bcrypt) Hash(password string) ([]byte, error) {
	return bcrypt.GenerateFromPassword([]byte(password), b.cost)
}

func (b *Bcrypt) Compare(hash []byte, password string) error {
	return bcrypt.CompareHashAndPassword(hash, []byte(password))
}
