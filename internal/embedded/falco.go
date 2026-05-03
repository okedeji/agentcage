package embedded

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/go-logr/logr"
)

const falcoVersion = "0.43.0"

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
	// Static binary runs on both glibc and musl. The VM rootfs is
	// Alpine (musl), so the default glibc-linked build won't work.
	url := fmt.Sprintf("https://download.falco.org/packages/bin/%s/falco-%s-static-%s.tar.gz",
		arch, falcoVersion, arch)

	f.log.Info("downloading falco", "version", falcoVersion, "url", url)

	archivePath := filepath.Join(BinDir(), "falco-"+falcoVersion+".tar.gz")
	if err := downloadBinaryWithLog(ctx, url, archivePath, f.log); err != nil {
		return fmt.Errorf("downloading falco: %w", err)
	}

	falcoDir := filepath.Join(BinDir(), "falco-"+falcoVersion)
	archive, err := os.Open(archivePath)
	if err != nil {
		return fmt.Errorf("opening falco archive: %w", err)
	}
	defer func() { _ = archive.Close() }()

	if err := extractTarGz(archive, falcoDir); err != nil {
		_ = os.Remove(archivePath)
		return fmt.Errorf("extracting falco: %w", err)
	}
	_ = os.Remove(archivePath)

	// The archive extracts with an arch-suffixed directory name
	// (e.g. falco-0.43.0-aarch64/usr/bin/falco).
	src := filepath.Join(falcoDir, fmt.Sprintf("falco-%s-static-%s", falcoVersion, arch), "usr", "bin", "falco")
	if err := os.Rename(src, dest); err != nil {
		return fmt.Errorf("moving falco binary: %w", err)
	}
	_ = os.RemoveAll(falcoDir)

	return nil
}

func (f *FalcoService) Start(ctx context.Context) error {
	bin := filepath.Join(BinDir(), "falco")
	rulesDir := filepath.Join(RunDir(), "falco", "rules.d")
	socketPath := filepath.Join(RunDir(), "falco", "falco.sock")

	_ = os.MkdirAll(filepath.Dir(socketPath), 0755)

	f.proc = newSubprocess("falco", f.log, bin,
		"--modern-bpf",
		"--json-output",
		"--rules-dir", rulesDir,
		"--unbuffered",
		"--unix-socket", socketPath,
	)

	if err := f.proc.start(ctx); err != nil {
		f.log.Info("falco failed to start, syscall monitoring unavailable (may require root)", "error", err)
		f.proc = nil
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
	// nil proc means Falco failed to start non-fatally (missing
	// binary, no root, no eBPF). This is an expected state in dev
	// mode, not a health failure.
	if f.proc == nil {
		return nil
	}
	if f.proc.cmd == nil || f.proc.cmd.Process == nil {
		return fmt.Errorf("falco not running")
	}
	return nil
}
