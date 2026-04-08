package main

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	"github.com/go-logr/logr"

	"github.com/okedeji/agentcage/internal/audit"
	"github.com/okedeji/agentcage/internal/cage"
	"github.com/okedeji/agentcage/internal/config"
	"github.com/okedeji/agentcage/internal/embedded"
	"github.com/okedeji/agentcage/internal/enforcement"
)

// cageRuntimeSetup is what setupCageRuntime returns.
type cageRuntimeSetup struct {
	provisioner cage.VMProvisioner
	isolated    bool
	rootfs      *cage.RootfsBuilder
	network     enforcement.NetworkEnforcer
	auditStore  *audit.PGStore
	falcoReader *cage.FalcoAlertReader
}

// setupCageRuntime wires the host machinery a cage needs to boot.
// Strict posture aborts on missing rootfs or unreachable Falco.
// allow_unisolated=true relaxes both for dev.
//
// Provisioner first: its isolated flag decides whether we want
// NFTables and a real rootfs (Firecracker) or neither (mock).
func setupCageRuntime(ctx context.Context, cfg *config.Config, db *sql.DB, log logr.Logger) (*cageRuntimeSetup, error) {
	fmt.Println("Setting up cage provisioner...")
	binDir := embedded.BinDir()
	log.Info("embedded bin dir", "path", binDir)

	firecrackerBin := cfg.CageRuntime.FirecrackerBin
	if firecrackerBin == "" {
		firecrackerBin = filepath.Join(binDir, "firecracker")
	}
	kernelBin := cfg.CageRuntime.KernelPath
	if kernelBin == "" {
		kernelBin = filepath.Join(binDir, "vmlinux")
	}

	provisioner, isolated, err := cage.BuildProvisioner(ctx, cage.HostRuntimeConfig{
		FirecrackerBin:  firecrackerBin,
		KernelPath:      kernelBin,
		AllowUnisolated: cfg.AllowUnisolatedDefault(),
	}, log)
	if err != nil {
		return nil, fmt.Errorf("setting up cage provisioner: %w", err)
	}

	var network enforcement.NetworkEnforcer
	if isolated {
		network = enforcement.NewNFTablesEnforcer(log)
	} else {
		network = enforcement.NewNoopEnforcer(log)
		log.Info("network enforcement disabled (unisolated cage runtime)")
	}

	auditStore := audit.NewPGStore(db)

	rootfs, err := buildRootfs(ctx, isolated, log)
	if err != nil {
		return nil, err
	}

	falcoReader, err := openFalcoReader(ctx, cfg, log)
	if err != nil {
		return nil, err
	}

	return &cageRuntimeSetup{
		provisioner: provisioner,
		isolated:    isolated,
		rootfs:      rootfs,
		network:     network,
		auditStore:  auditStore,
		falcoReader: falcoReader,
	}, nil
}

// buildRootfs prepares the rootfs builder. The base image is only
// required for real Firecracker. A stale-state sweep runs on startup;
// failures log and continue.
func buildRootfs(ctx context.Context, isolated bool, log logr.Logger) (*cage.RootfsBuilder, error) {
	baseRootfs := filepath.Join(embedded.VMDir(), "cage-rootfs.img")
	rootfsWorkDir := filepath.Join(embedded.DataDir(), "rootfs-work")
	if err := os.MkdirAll(rootfsWorkDir, 0755); err != nil {
		return nil, fmt.Errorf("creating rootfs work directory: %w", err)
	}
	if isolated {
		if reason := cage.CheckBaseRootfs(baseRootfs); reason != "" {
			return nil, fmt.Errorf("base rootfs not usable (%s): cages cannot be assembled without it", reason)
		}
		log.Info("base rootfs OK", "path", baseRootfs)
	}
	builder := cage.NewRootfsBuilder(baseRootfs, rootfsWorkDir, version)
	if err := builder.SweepStale(ctx, log); err != nil {
		log.Error(err, "sweeping stale rootfs state, continuing")
	}
	return builder, nil
}

// writeFalcoRules writes the generated ruleset to disk. Must run
// before the Falco daemon starts.
func writeFalcoRules(cfg *config.Config, log logr.Logger) (cage.AlertHandler, error) {
	fmt.Println("Generating Falco rules...")
	rules, tripwires := enforcement.GenerateFalcoRules(cfg.Monitoring)
	handler := enforcement.NewFalcoHandlerFromGenerated(tripwires)
	alertHandler := enforcement.NewFalcoAlertAdapter(handler)

	rulesDir := filepath.Join(embedded.RunDir(), "falco", "rules.d")
	if err := enforcement.WriteFalcoRules(rules, rulesDir); err != nil {
		return nil, fmt.Errorf("writing Falco rules: %w", err)
	}
	log.Info("Falco rules written", "dir", rulesDir)
	return alertHandler, nil
}

// openFalcoReader connects to the Falco unix socket. Falco is the
// only behavioral tripwire we have, so a missing Falco is fatal in
// strict posture.
func openFalcoReader(ctx context.Context, cfg *config.Config, log logr.Logger) (*cage.FalcoAlertReader, error) {
	socket := filepath.Join(embedded.RunDir(), "falco", "falco.sock")
	if cfg.Infrastructure.Falco != nil && cfg.Infrastructure.Falco.Socket != "" {
		socket = cfg.Infrastructure.Falco.Socket
	}

	if reason := cage.CheckFalcoSocket(ctx, socket); reason != "" {
		if !cfg.AllowUnisolatedDefault() {
			return nil, fmt.Errorf("falco not usable (%s); set cage_runtime.allow_unisolated=true to run cages without behavioral tripwires", reason)
		}
		log.Info("WARNING: Falco unavailable, cages will run without behavioral tripwires",
			"socket", socket, "reason", reason)
		return nil, nil
	}

	log.Info("Falco alert reader configured", "socket", socket)
	return cage.NewFalcoAlertReader(socket, log), nil
}
