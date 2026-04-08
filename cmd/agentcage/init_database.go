package main

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"

	"github.com/go-logr/logr"
	_ "github.com/lib/pq"

	"github.com/okedeji/agentcage/internal/config"
	"github.com/okedeji/agentcage/internal/embedded"
	"github.com/okedeji/agentcage/migrations"
)

// connectDatabase opens the embedded or external Postgres, pings, and
// runs migrations. Caller closes the db.
func connectDatabase(ctx context.Context, cfg *config.Config, log logr.Logger) (*sql.DB, error) {
	var dbURL string
	if cfg.Infrastructure.IsExternalPostgres() {
		dbURL = cfg.Infrastructure.Postgres.URL
	} else {
		var urlErr error
		dbURL, urlErr = embedded.PostgresURL()
		if urlErr != nil {
			return nil, fmt.Errorf("resolving embedded Postgres URL: %w", urlErr)
		}
	}

	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		return nil, fmt.Errorf("opening database: %w", err)
	}

	fmt.Println("Connecting to database...")
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("connecting to database: %w", err)
	}
	log.Info("database connected", "url", redactDBURL(dbURL))

	fmt.Println("Running database migrations...")
	applied, err := migrations.Up(ctx, db)
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("running migrations: %w", err)
	}
	if len(applied) > 0 {
		fmt.Printf("  %d migration(s) applied.\n", len(applied))
	}
	for _, name := range applied {
		log.Info("migration applied", "name", name)
	}
	return db, nil
}

// redactDBURL replaces the password in a Postgres URL. Returns "***"
// on parse failure so we never log raw credentials.
func redactDBURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "***"
	}
	if u.User != nil {
		u.User = url.UserPassword(u.User.Username(), "***")
	}
	return u.String()
}
