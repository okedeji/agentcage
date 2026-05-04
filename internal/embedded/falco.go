package embedded

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/go-logr/logr"
)

// FalcoService manages an embedded Falco runtime security monitor.
// Falco watches syscalls from cage VMs and emits alerts that agentcage's
// tripwire system handles.
type FalcoService struct {
	proc    *subprocess
	log     logr.Logger
	version string
}

func NewFalcoService(log logr.Logger, version string) *FalcoService {
	return &FalcoService{log: log.WithValues("service", "falco"), version: version}
}

func (f *FalcoService) Name() string      { return "falco" }
func (f *FalcoService) IsExternal() bool   { return false }

func (f *FalcoService) Download(ctx context.Context) error {
	dest := filepath.Join(BinDir(), "falco")
	if _, err := os.Stat(dest); err == nil {
		return nil
	}

	// Built from source with -DMUSL_OPTIMIZED_BUILD=ON in our
	// release CI. Native musl binary, no gcompat shim needed.
	arch := runtime.GOARCH
	url := fmt.Sprintf("https://github.com/okedeji/agentcage/releases/download/v%s/falco-%s",
		f.version, arch)

	f.log.Info("downloading falco", "url", url)
	if err := downloadBinaryWithLog(ctx, url, dest, f.log); err != nil {
		return fmt.Errorf("downloading falco: %w", err)
	}
	return os.Chmod(dest, 0755)
}

// AlertFilePath returns where Falco writes JSON alert lines.
func (f *FalcoService) AlertFilePath() string {
	return filepath.Join(RunDir(), "falco", "alerts.jsonl")
}

func (f *FalcoService) Start(ctx context.Context) error {
	bin := filepath.Join(BinDir(), "falco")
	rulesDir := filepath.Join(RunDir(), "falco", "rules.d")
	alertFile := f.AlertFilePath()
	confFile := filepath.Join(RunDir(), "falco", "falco.yaml")

	_ = os.MkdirAll(filepath.Dir(alertFile), 0755)

	// Falco requires a base config file even when all settings are
	// overridden via -o flags. Write a minimal one.
	if err := os.WriteFile(confFile, []byte("# agentcage-managed\n"), 0644); err != nil {
		return fmt.Errorf("writing falco config: %w", err)
	}

	f.proc = newSubprocess("falco", f.log, bin,
		"-c", confFile,
		"-o", "engine.kind=modern_ebpf",
		"-o", "json_output=true",
		"-o", "buffered_outputs=false",
		"-o", "file_output.enabled=true",
		"-o", "file_output.filename="+alertFile,
		"-o", "file_output.keep_alive=true",
		"-r", rulesDir,
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
