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
	url := fmt.Sprintf("https://download.falco.org/packages/bin/%s/falco-%s-%s.tar.gz",
		arch, falcoVersion, arch)

	f.log.Info("downloading falco", "version", falcoVersion, "url", url)

	archivePath := filepath.Join(BinDir(), "falco-"+falcoVersion+".tar.gz")
	if err := downloadBinary(ctx, url, archivePath); err != nil {
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

	// Move falco binary to BinDir
	src := filepath.Join(falcoDir, "usr", "bin", "falco")
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
		"--rules-file", filepath.Join(rulesDir, "agentcage_rules.yaml"),
		"--unbuffered",
		"--unix-socket", socketPath,
	)

	if err := f.proc.start(ctx); err != nil {
		f.log.Info("falco failed to start, syscall monitoring unavailable (may require root)", "error", err)
		// Non-fatal: agentcage can run without Falco in local mode
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
