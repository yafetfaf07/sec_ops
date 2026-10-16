package database

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

type Options struct {
	MaxOpenConns    int
	MaxIdleConns    int
	ConnMaxLifetime time.Duration
}

// Connect opens a GORM connection to Postgres and verifies it with a ping.
//
// The pgx simple protocol is enabled because hosted free-tier Postgres
// (Neon, Supabase) is usually reached through a transaction-mode pooler that
// does not support prepared statements; it also allows the multi-statement
// migration files to run in one Exec. Queries remain parameterised.
//
// Schema is NOT managed here (no AutoMigrate): call Migrate on the returned
// *sql.DB. AutoMigrate cannot express triggers, CHECKs or partial indexes.
func Connect(ctx context.Context, databaseURL string, opts Options) (*gorm.DB, *sql.DB, error) {
	gdb, err := gorm.Open(postgres.New(postgres.Config{
		DSN:                  databaseURL,
		PreferSimpleProtocol: true,
	}), &gorm.Config{
		Logger:         logger.Default.LogMode(logger.Warn),
		TranslateError: true,
		NowFunc:        func() time.Time { return time.Now().UTC() },
	})
	if err != nil {
		// Do not wrap the DSN into the message; drivers may echo it.
		return nil, nil, fmt.Errorf("open database: %w", err)
	}

	sqlDB, err := gdb.DB()
	if err != nil {
		return nil, nil, fmt.Errorf("get sql.DB: %w", err)
	}
	sqlDB.SetMaxOpenConns(opts.MaxOpenConns)
	sqlDB.SetMaxIdleConns(opts.MaxIdleConns)
	sqlDB.SetConnMaxLifetime(opts.ConnMaxLifetime)

	pingCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := sqlDB.PingContext(pingCtx); err != nil {
		_ = sqlDB.Close()
		return nil, nil, fmt.Errorf("ping database: %w", err)
	}
	return gdb, sqlDB, nil
}
