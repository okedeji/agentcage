package embedded

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/go-logr/logr"
)

const falcoVersion = "0.37.0"

// FalcoService manages an embedded Falco runtime security monitor.
// Falco watches syscalls from cage VMs and emits alerts that agentcage's
// tripwire system handles.
type FalcoService struct {
	proc *subprocess
	log  logr.Logger
}

func NewFalcoService(log logr.Logger) *FalcoService {
	return &FalcoService{log: log.WithValues("service", "falco")}
}

func (f *FalcoService) Name() string      { return "falco" }
func (f *FalcoService) IsExternal() bool   { return false }

func (f *FalcoService) Download(ctx context.Context) error {
	dest := filepath.Join(BinDir(), "falco")
	if _, err := os.Stat(dest); err == nil {
		return nil
	}

	arch := archSuffix()
	osName := runtime.GOOS
	url := fmt.Sprintf("https://download.falco.org/packages/bin/%s/%s/falco-%s-%s-%s.tar.gz",
		osName, arch, falcoVersion, osName, arch)

	// Stub: real implementation would download and extract the tarball.
	_ = url

	if err := os.WriteFile(dest, []byte("#!/bin/sh\necho stub"), 0755); err != nil {
		return fmt.Errorf("creating stub falco: %w", err)
	}
	return nil
}

func (f *FalcoService) Start(ctx context.Context) error {
	bin := filepath.Join(BinDir(), "falco")

	// Falco requires root/privileged access for syscall monitoring.
	// In embedded mode, we start it and let it fail gracefully if
	// privileges are insufficient (dev mode on laptop vs production).
	f.proc = newSubprocess("falco", f.log, bin,
		"--modern-bpf",
		"--json-output",
	)

	if err := f.proc.start(ctx); err != nil {
		f.log.Info("falco failed to start — syscall monitoring unavailable (may require root)", "error", err)
		// Non-fatal: agentcage can run without Falco in dev mode
		return nil
	}

	f.log.Info("falco started")
	return nil
}

func (f *FalcoService) Stop(ctx context.Context) error {
	if f.proc == nil {
		return nil
	}
	return f.proc.stop(ctx)
}

func (f *FalcoService) Health(_ context.Context) error {
	if f.proc == nil || f.proc.cmd == nil || f.proc.cmd.Process == nil {
		return fmt.Errorf("falco not running")
	}
	return nil
}
