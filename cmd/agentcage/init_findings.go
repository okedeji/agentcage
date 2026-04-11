package main

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/go-logr/logr"
	"github.com/nats-io/nats.go"
	"github.com/spiffe/go-spiffe/v2/spiffeid"

	"github.com/okedeji/agentcage/internal/config"
	"github.com/okedeji/agentcage/internal/embedded"
	"github.com/okedeji/agentcage/internal/findings"
	"github.com/okedeji/agentcage/internal/identity"
)

func resolveNATSURL(ctx context.Context, cfg *config.Config, secrets identity.SecretReader) (string, error) {
	if !cfg.Infrastructure.IsExternalNATS() {
		return embedded.NATSURL(), nil
	}
	if secrets == nil {
		return "", fmt.Errorf("external NATS requires Vault: store the connection URL at %s", identity.PathNATSURL)
	}
	val, err := identity.ReadSecretValue(ctx, secrets, identity.PathNATSURL)
	if err != nil || val == "" {
		return "", fmt.Errorf("reading NATS URL from Vault (%s): %w", identity.PathNATSURL, err)
	}
	return val, nil
}

// Bloom filter catches dupes before we hit Postgres on the hot path.
func connectFindingsBus(ctx context.Context, cfg *config.Config, natsURL string, spireSocket string, trustDomain spiffeid.TrustDomain, db *sql.DB, log logr.Logger) (findings.Bus, *findings.PGStore, *findings.Coordinator, error) {
	var natsOpts []nats.Option
	if cfg.Infrastructure.IsExternalNATS() {
		if tlsCfg := buildSPIREClientTLS(ctx, spireSocket, trustDomain); tlsCfg != nil {
			natsOpts = append(natsOpts, nats.Secure(tlsCfg))
			log.Info("NATS mTLS enabled via SPIRE")
		}
	}

	fmt.Println("Connecting to NATS findings bus...")
	bus, err := findings.NewNATSBus(natsURL, natsOpts...)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("connecting to NATS at %s: %w", natsURL, err)
	}

	store := findings.NewPGStore(db)
	bloom := findings.NewBloomFilter(100000, 7)
	var sanitizeLimits *findings.SanitizeLimits
	if cfg.Assessment.MaxScreenshotSize > 0 {
		sanitizeLimits = &findings.SanitizeLimits{MaxScreenshotSize: cfg.Assessment.MaxScreenshotSize}
	}
	coordinator := findings.NewCoordinator(store, bloom, sanitizeLimits, log.WithValues("component", "findings-coordinator"))

	log.Info("findings bus connected", "url", natsURL)
	return bus, store, coordinator, nil
}
