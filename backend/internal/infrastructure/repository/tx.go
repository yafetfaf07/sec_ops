// Package repository implements the domain repository ports with GORM.
package repository

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5/pgconn"
	"gorm.io/gorm"

	"sec_ops/internal/domain/interfaces"
)

type txKey struct{}

// TxManager stores the active *gorm.DB transaction in the context so every
// repository call made with that context joins it.
type TxManager struct{ db *gorm.DB }

var _ interfaces.TxManager = (*TxManager)(nil)

func NewTxManager(db *gorm.DB) *TxManager { return &TxManager{db: db} }

func (m *TxManager) WithinTx(ctx context.Context, fn func(ctx context.Context) error) error {
	if _, ok := ctx.Value(txKey{}).(*gorm.DB); ok {
		return fn(ctx) // already inside a transaction
	}
	return m.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		return fn(context.WithValue(ctx, txKey{}, tx))
	})
}

// conn returns the transaction from ctx, or the base pool.
func conn(ctx context.Context, db *gorm.DB) *gorm.DB {
	if tx, ok := ctx.Value(txKey{}).(*gorm.DB); ok {
		return tx.WithContext(ctx)
	}
	return db.WithContext(ctx)
}

// translate maps driver errors onto domain sentinels. The original error is
// kept in the chain (errors.Join) for server-side logging.
func translate(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return interfaces.ErrNotFound
	}
	var pg *pgconn.PgError
	if errors.As(err, &pg) {
		switch pg.Code {
		case "23505":
			return errors.Join(interfaces.ErrConflict, err)
		case "23001":
			return errors.Join(interfaces.ErrImmutable, err)
		case "23514", "22P02", "23502", "22001":
			return errors.Join(interfaces.ErrValidation, err)
		case "23503":
			return errors.Join(interfaces.ErrNotFound, err)
		}
	}
	if errors.Is(err, gorm.ErrDuplicatedKey) {
		return errors.Join(interfaces.ErrConflict, err)
	}
	if errors.Is(err, gorm.ErrCheckConstraintViolated) || errors.Is(err, gorm.ErrInvalidData) {
		return errors.Join(interfaces.ErrValidation, err)
	}
	if errors.Is(err, gorm.ErrForeignKeyViolated) {
		return errors.Join(interfaces.ErrNotFound, err)
	}
	return err
}

func clampLimit(n, def, max int) int {
	if n <= 0 {
		return def
	}
	if n > max {
		return max
	}
	return n
}
