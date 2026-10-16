package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
)

// Integration tests run only when TEST_DATABASE_URL points at a disposable
// Postgres (e.g. a Neon dev branch). Each test run creates its own schema via
// search_path and drops it afterwards, so it never touches existing tables.
func openTestDB(t *testing.T) *sql.DB {
	t.Helper()
	raw := os.Getenv("TEST_DATABASE_URL")
	if raw == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping database integration test")
	}

	schema := "test_" + strings.ReplaceAll(uuid.NewString(), "-", "")[:12]
	ctx := context.Background()

	_, admin, err := Connect(ctx, raw, Options{MaxOpenConns: 2, MaxIdleConns: 1, ConnMaxLifetime: time.Minute})
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if _, err := admin.ExecContext(ctx, fmt.Sprintf(`CREATE SCHEMA %s`, schema)); err != nil {
		t.Fatalf("create schema: %v", err)
	}

	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse TEST_DATABASE_URL: %v", err)
	}
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()

	_, db, err := Connect(ctx, u.String(), Options{MaxOpenConns: 2, MaxIdleConns: 1, ConnMaxLifetime: time.Minute})
	if err != nil {
		t.Fatalf("connect schema: %v", err)
	}
	t.Cleanup(func() {
		_ = db.Close()
		_, _ = admin.ExecContext(context.Background(), fmt.Sprintf(`DROP SCHEMA %s CASCADE`, schema))
		_ = admin.Close()
	})
	return db
}

func TestMigrateIsIdempotentAndEnforcesImmutability(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	if err := Migrate(ctx, db, log); err != nil {
		t.Fatalf("first migrate: %v", err)
	}
	if err := Migrate(ctx, db, log); err != nil {
		t.Fatalf("second migrate must be a no-op: %v", err)
	}

	if _, err := db.ExecContext(ctx, `INSERT INTO raw_logs (log_id, ts, user_id, ip_address, action, flagged)
		VALUES ('l1', now(), 'u1', '203.0.113.7', 'Login Failed', true)`); err != nil {
		t.Fatalf("insert raw log: %v", err)
	}

	// The flag must agree with the action.
	_, err := db.ExecContext(ctx, `INSERT INTO raw_logs (log_id, ts, user_id, ip_address, action, flagged)
		VALUES ('l2', now(), 'u1', '203.0.113.7', 'Login Success', true)`)
	assertSQLState(t, err, "23514") // check_violation

	for _, stmt := range []string{
		`UPDATE raw_logs SET city = 'x' WHERE log_id = 'l1'`,
		`DELETE FROM raw_logs WHERE log_id = 'l1'`,
		`TRUNCATE raw_logs CASCADE`,
	} {
		_, err := db.ExecContext(ctx, stmt)
		assertSQLState(t, err, "23001") // restrict_violation from forbid_mutation()
	}

	if _, err := db.ExecContext(ctx, `INSERT INTO audit_logs (user_id, action_type, hash) VALUES ('SYSTEM', 'TEST', 'h')`); err != nil {
		t.Fatalf("insert audit: %v", err)
	}
	_, err = db.ExecContext(ctx, `DELETE FROM audit_logs`)
	assertSQLState(t, err, "23001")
}

func assertSQLState(t *testing.T, err error, code string) {
	t.Helper()
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		t.Fatalf("expected Postgres error %s, got %v", code, err)
	}
	if pgErr.Code != code {
		t.Fatalf("expected SQLSTATE %s, got %s (%s)", code, pgErr.Code, pgErr.Message)
	}
}
