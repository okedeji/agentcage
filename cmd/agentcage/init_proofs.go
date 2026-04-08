package main

import (
	"fmt"
	"os"

	"github.com/go-logr/logr"

	"github.com/okedeji/agentcage/internal/assessment"
	"github.com/okedeji/agentcage/internal/config"
)

// loadProofLibrary loads validation proofs from disk. Bundled mode
// seeds defaults if missing; BYOP leaves it to the operator and
// unfamiliar vuln classes trigger proof_gap interventions until proofs
// are added. A malformed YAML is fatal so a broken rule can't ship.
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
