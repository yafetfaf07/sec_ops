// Package security implements the password hashing, token and OIDC ports.
package security

import (
	"errors"
	"fmt"

	"golang.org/x/crypto/bcrypt"

	"sec_ops/internal/domain/interfaces"
)

type BcryptHasher struct{ cost int }

var _ interfaces.PasswordHasher = (*BcryptHasher)(nil)

func NewBcryptHasher(cost int) *BcryptHasher {
	if cost < bcrypt.MinCost {
		cost = bcrypt.DefaultCost
	}
	return &BcryptHasher{cost: cost}
}

func (b *BcryptHasher) Hash(password string) (string, error) {
	if len(password) > 72 {
		// bcrypt silently truncates beyond 72 bytes; refuse instead.
		return "", fmt.Errorf("%w: password longer than 72 bytes", interfaces.ErrValidation)
	}
	h, err := bcrypt.GenerateFromPassword([]byte(password), b.cost)
	if err != nil {
		return "", err
	}
	return string(h), nil
}

func (b *BcryptHasher) Compare(hash, password string) error {
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)); err != nil {
		if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
			return interfaces.ErrUnauthorized
		}
		return err
	}
	return nil
}

// dummyHash is compared against when a login email does not exist, so the
// response time does not reveal which emails are registered.
var dummyHash, _ = bcrypt.GenerateFromPassword([]byte("timing-equaliser-not-a-password"), bcrypt.DefaultCost)

func (b *BcryptHasher) CompareDummy(password string) {
	_ = bcrypt.CompareHashAndPassword(dummyHash, []byte(password))
}
