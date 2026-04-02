package migrations

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"io/fs"
	"sort"
	"strings"
)

//go:embed *.sql
var sqlFiles embed.FS

// Up applies all pending SQL migrations in order. Each migration runs
// inside a transaction — if the SQL fails, the transaction rolls back
// and the migration is not recorded.
func Up(ctx context.Context, db *sql.DB) ([]string, error) {
	if err := ensureMigrationsTable(ctx, db); err != nil {
		return nil, fmt.Errorf("creating migrations table: %w", err)
	}

	applied, err := getAppliedMigrations(ctx, db)
	if err != nil {
		return nil, fmt.Errorf("reading applied migrations: %w", err)
	}

	files, err := listMigrationFiles()
	if err != nil {
		return nil, fmt.Errorf("listing migration files: %w", err)
	}

	var ran []string
	for _, name := range files {
		if applied[name] {
			continue
		}

		upSQL, err := extractSection(name, "-- +migrate Up")
		if err != nil {
			return ran, fmt.Errorf("parsing migration %s: %w", name, err)
		}

		if err := applyInTx(ctx, db, name, upSQL, true); err != nil {
			return ran, err
		}

		ran = append(ran, name)
	}

	return ran, nil
}

// Down rolls back the last `steps` applied migrations in reverse order.
// Each rollback runs inside a transaction.
func Down(ctx context.Context, db *sql.DB, steps int) ([]string, error) {
	if err := ensureMigrationsTable(ctx, db); err != nil {
		return nil, fmt.Errorf("creating migrations table: %w", err)
	}

	applied, err := getAppliedMigrationsOrdered(ctx, db)
	if err != nil {
		return nil, fmt.Errorf("reading applied migrations: %w", err)
	}

	if steps <= 0 || steps > len(applied) {
		steps = len(applied)
	}

	var rolled []string
	for i := 0; i < steps; i++ {
		name := applied[len(applied)-1-i]

		downSQL, err := extractSection(name, "-- +migrate Down")
		if err != nil {
			return rolled, fmt.Errorf("parsing down migration %s: %w", name, err)
		}

		if err := applyInTx(ctx, db, name, downSQL, false); err != nil {
			return rolled, err
		}

		rolled = append(rolled, name)
	}

	return rolled, nil
}

func applyInTx(ctx context.Context, db *sql.DB, name, sqlStr string, isUp bool) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("beginning transaction for %s: %w", name, err)
	}

	if _, err := tx.ExecContext(ctx, sqlStr); err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("applying migration %s: %w", name, err)
	}

	if isUp {
		if _, err := tx.ExecContext(ctx,
			"INSERT INTO schema_migrations (name) VALUES ($1)", name,
		); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("recording migration %s: %w", name, err)
		}
	} else {
		if _, err := tx.ExecContext(ctx,
			"DELETE FROM schema_migrations WHERE name = $1", name,
		); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("removing migration record %s: %w", name, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("committing migration %s: %w", name, err)
	}
	return nil
}

func ensureMigrationsTable(ctx context.Context, db *sql.DB) error {
	_, err := db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			name       TEXT PRIMARY KEY,
			applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)
	`)
	return err
}

func getAppliedMigrations(ctx context.Context, db *sql.DB) (map[string]bool, error) {
	rows, err := db.QueryContext(ctx, "SELECT name FROM schema_migrations")
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	applied := make(map[string]bool)
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		applied[name] = true
	}
	return applied, rows.Err()
}

func getAppliedMigrationsOrdered(ctx context.Context, db *sql.DB) ([]string, error) {
	rows, err := db.QueryContext(ctx, "SELECT name FROM schema_migrations ORDER BY name ASC")
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		names = append(names, name)
	}
	return names, rows.Err()
}

func listMigrationFiles() ([]string, error) {
	entries, err := fs.ReadDir(sqlFiles, ".")
	if err != nil {
		return nil, err
	}

	var names []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".sql") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	return names, nil
}

func extractSection(name, marker string) (string, error) {
	data, err := sqlFiles.ReadFile(name)
	if err != nil {
		return "", err
	}

	content := string(data)

	idx := strings.Index(content, marker)
	if idx < 0 {
		return "", fmt.Errorf("no '%s' marker found in %s", marker, name)
	}

	rest := content[idx+len(marker):]

	for _, other := range []string{"-- +migrate Up", "-- +migrate Down"} {
		if other == marker {
			continue
		}
		if endIdx := strings.Index(rest, other); endIdx >= 0 {
			rest = rest[:endIdx]
		}
	}

	return strings.TrimSpace(rest), nil
}
