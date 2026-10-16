package database

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"io/fs"
	"log/slog"
	"path"
	"regexp"
	"sort"
	"strconv"
)

//go:embed migrations/*.sql
var migrationFiles embed.FS

// migrationLockKey is an arbitrary constant shared by every instance so only
// one process applies migrations at a time (Cloud Run may start several
// instances concurrently during a rollout).
const migrationLockKey int64 = 0x5EC0_0001

var migrationName = regexp.MustCompile(`^(\d{4})_[a-z0-9_]+\.sql$`)

// Migration is one embedded SQL file. Files are named NNNN_description.sql,
// applied in version order, each in its own transaction, and never edited
// after they have been applied anywhere: add a new file instead.
type Migration struct {
	Version int
	Name    string
	SQL     string
}

// LoadMigrations returns the embedded migrations sorted by version and checks
// that versions are unique and contiguous starting at 1.
func LoadMigrations() ([]Migration, error) {
	return loadMigrationsFrom(migrationFiles, "migrations")
}

func loadMigrationsFrom(fsys fs.FS, dir string) ([]Migration, error) {
	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return nil, fmt.Errorf("read migrations: %w", err)
	}

	var out []Migration
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		m := migrationName.FindStringSubmatch(e.Name())
		if m == nil {
			return nil, fmt.Errorf("migration %q does not match NNNN_name.sql", e.Name())
		}
		version, _ := strconv.Atoi(m[1])
		body, err := fs.ReadFile(fsys, path.Join(dir, e.Name()))
		if err != nil {
			return nil, fmt.Errorf("read migration %s: %w", e.Name(), err)
		}
		out = append(out, Migration{Version: version, Name: e.Name(), SQL: string(body)})
	}

	sort.Slice(out, func(i, j int) bool { return out[i].Version < out[j].Version })
	for i, m := range out {
		if m.Version != i+1 {
			return nil, fmt.Errorf("migration versions must be contiguous from 0001: expected %04d, found %s", i+1, m.Name)
		}
	}
	return out, nil
}

// Migrate applies all pending migrations. It needs a connection that allows
// multi-statement Exec (Connect enables the pgx simple protocol for this).
//
// Each migration runs in its own transaction that first takes a
// transaction-scoped advisory lock and re-checks schema_migrations. Session
// locks are deliberately avoided: behind a transaction-mode pooler (Neon,
// Supabase) consecutive statements can land on different server connections,
// so a session lock could be taken on one and "released" on another.
func Migrate(ctx context.Context, db *sql.DB, log *slog.Logger) error {
	migrations, err := LoadMigrations()
	if err != nil {
		return err
	}

	if err := withLockedTx(ctx, db, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
			version    integer PRIMARY KEY,
			name       text        NOT NULL,
			applied_at timestamptz NOT NULL DEFAULT now()
		)`)
		return err
	}); err != nil {
		return fmt.Errorf("create schema_migrations: %w", err)
	}

	for _, m := range migrations {
		applied := false
		err := withLockedTx(ctx, db, func(tx *sql.Tx) error {
			var exists bool
			if err := tx.QueryRowContext(ctx,
				`SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE version = $1)`, m.Version).Scan(&exists); err != nil {
				return err
			}
			if exists {
				return nil
			}
			if _, err := tx.ExecContext(ctx, m.SQL); err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx,
				`INSERT INTO schema_migrations (version, name) VALUES ($1, $2)`, m.Version, m.Name); err != nil {
				return err
			}
			applied = true
			return nil
		})
		if err != nil {
			return fmt.Errorf("apply migration %s: %w", m.Name, err)
		}
		if applied {
			log.Info("migration applied", "version", m.Version, "name", m.Name)
		}
	}
	return nil
}

func withLockedTx(ctx context.Context, db *sql.DB, fn func(tx *sql.Tx) error) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1)`, migrationLockKey); err != nil {
		_ = tx.Rollback()
		return err
	}
	if err := fn(tx); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}
