package main

import (
	"fmt"
	"os"

	"github.com/go-logr/logr"

	"github.com/okedeji/agentcage/internal/assessment"
	"github.com/okedeji/agentcage/internal/config"
)

// A malformed proof YAML is fatal so a broken validation rule
// can't reach a running assessment.
func loadProofLibrary(cfg *config.Config, log logr.Logger) (*assessment.ProofLibrary, error) {
	dir := cfg.Assessment.ProofsDir
	if dir == "" {
		dir = proofsDir()
	}
	fmt.Println("Loading validation rules...")

	switch cfg.Assessment.ProofsMode {
	case config.ProofsModeBYOP:
		log.Info("proofs mode: byop (no defaults seeded)")
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, fmt.Errorf("creating proofs directory %s: %w", dir, err)
		}
	default:
		log.Info("proofs mode: bundled (seeding any missing defaults)")
		if err := seedDefaultProofs(dir); err != nil {
			return nil, fmt.Errorf("seeding default proofs: %w", err)
		}
	}

	lib, err := assessment.LoadProofs(dir)
	if err != nil {
		return nil, fmt.Errorf("loading proofs from %s: %w", dir, err)
	}
	log.Info("proofs loaded", "dir", dir, "count", len(lib.List()))
	return lib, nil
}
