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
	"github.com/okedeji/agentcage/internal/identity"
	"github.com/okedeji/agentcage/internal/ui"
	"github.com/okedeji/agentcage/migrations"
)

func connectDatabase(ctx context.Context, cfg *config.Config, secrets identity.SecretReader, log logr.Logger) (*sql.DB, error) {
	var dbURL string
	if cfg.Infrastructure.IsExternalPostgres() {
		if secrets == nil {
			return nil, fmt.Errorf("external Postgres requires Vault: store the connection URL at %s", identity.PathPostgresURL)
		}
		val, err := identity.ReadSecretValue(ctx, secrets, identity.PathPostgresURL)
		if err != nil || val == "" {
			return nil, fmt.Errorf("reading Postgres URL from Vault (%s): %w", identity.PathPostgresURL, err)
		}
		dbURL = val
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

	ui.Step("Connecting to database")
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("connecting to database: %w", err)
	}
	log.Info("database connected", "url", redactDBURL(dbURL))

	ui.Step("Running migrations")
	applied, err := migrations.Up(ctx, db)
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("running migrations: %w", err)
	}
	if len(applied) > 0 {
		ui.OK("%d migration(s) applied", len(applied))
	}
	for _, name := range applied {
		log.Info("migration applied", "name", name)
	}
	return db, nil
}

// Returns "***" on parse failure so we never log raw credentials.
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
