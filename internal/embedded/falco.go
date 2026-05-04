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
