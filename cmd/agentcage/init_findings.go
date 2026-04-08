package main

import (
	"database/sql"
	"fmt"

	"github.com/go-logr/logr"

	"github.com/okedeji/agentcage/internal/config"
	"github.com/okedeji/agentcage/internal/embedded"
	"github.com/okedeji/agentcage/internal/findings"
)

// connectFindingsBus connects to NATS and builds the store and
// coordinator on top. Caller closes the bus.
//
// Bloom filter sized for 100k findings, 7 hash functions. The bloom
// catches dupes before we hit Postgres on the hot path.
func connectFindingsBus(cfg *config.Config, db *sql.DB, log logr.Logger) (findings.Bus, *findings.PGStore, *findings.Coordinator, error) {
	natsURL := embedded.NATSURL()
	if cfg.Infrastructure.IsExternalNATS() {
		natsURL = cfg.Infrastructure.NATS.URL
	}

	fmt.Println("Connecting to NATS findings bus...")
	bus, err := findings.NewNATSBus(natsURL)
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
