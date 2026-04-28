package main

import (
	"fmt"
	"os"

	"github.com/go-logr/logr"

	"github.com/okedeji/agentcage/internal/assessment"
	"github.com/okedeji/agentcage/internal/config"
	"github.com/okedeji/agentcage/internal/ui"
)

// A malformed proof YAML is fatal so a broken validation rule
// can't reach a running assessment.
func loadProofLibrary(cfg *config.Config, log logr.Logger) (*assessment.ProofLibrary, error) {
	dir := cfg.Assessment.ProofsDir
	if dir == "" {
		dir = proofsDir()
	}
	ui.Step("Loading validation rules")

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
	count := len(lib.List())
	if count == 0 {
		fmt.Fprintln(os.Stderr, "warning: no validation proofs loaded. Findings will remain as candidates without validation.")
		fmt.Fprintln(os.Stderr, "  Add proofs with: agentcage proof add <file.yaml>")
	}
	log.Info("proofs loaded", "dir", dir, "count", count)
	return lib, nil
}
