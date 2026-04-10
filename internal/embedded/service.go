package embedded

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"

	"github.com/go-logr/logr"

	"github.com/okedeji/agentcage/internal/envvar"
)

// Service is the lifecycle interface for an embedded infrastructure component.
// Each implementation manages downloading, starting, stopping, and health
// checking a single service (Postgres, Temporal, SPIRE, Vault, Falco, etc.).
type Service interface {
	Name() string
	Download(ctx context.Context) error
	Start(ctx context.Context) error
	Stop(ctx context.Context) error
	Health(ctx context.Context) error
	IsExternal() bool
}

// DataDir returns the root data directory for agentcage embedded services.
// Defaults to ~/.agentcage if AGENTCAGE_HOME is not set.
func DataDir() string {
	if d := os.Getenv(envvar.Home); d != "" {
		return d
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ".agentcage"
	}
	return filepath.Join(home, ".agentcage")
}

// BinDir returns the directory where downloaded binaries are stored.
func BinDir() string {
	return filepath.Join(DataDir(), "bin")
}

// LogDir returns the directory where service logs are written.
func LogDir() string {
	return filepath.Join(DataDir(), "logs")
}

// VMDir returns the directory where VM assets (kernel, rootfs, linux binary) are stored.
func VMDir() string {
	return filepath.Join(DataDir(), "vm")
}

// RunDir returns the directory for runtime state (PID files, sockets).
func RunDir() string {
	return filepath.Join(DataDir(), "run")
}

// ServiceDataDir returns the data directory for a specific service.
func ServiceDataDir(name string) string {
	return filepath.Join(DataDir(), "data", name)
}

// EnsureDirs creates the standard agentcage directory structure.
func EnsureDirs() error {
	dirs := []string{
		BinDir(),
		LogDir(),
		RunDir(),
		ServiceDataDir("postgres"),
		ServiceDataDir("temporal"),
		ServiceDataDir("nats"),
		ServiceDataDir("spire"),
		ServiceDataDir("vault"),
		VMDir(),
	}
	for _, d := range dirs {
		if err := os.MkdirAll(d, 0755); err != nil {
			return fmt.Errorf("creating directory %s: %w", d, err)
		}
	}
	return nil
}

// downloadBinary fetches a URL and writes it to dest with executable permissions.
func downloadBinary(ctx context.Context, url, dest string) error {
	if err := os.MkdirAll(filepath.Dir(dest), 0755); err != nil {
		return fmt.Errorf("creating directory for %s: %w", dest, err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("creating request for %s: %w", url, err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("downloading %s: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("downloading %s: status %d", url, resp.StatusCode)
	}

	tmp := dest + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
	if err != nil {
		return fmt.Errorf("creating file %s: %w", tmp, err)
	}

	if _, err := io.Copy(f, resp.Body); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("writing %s: %w", dest, err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("closing %s: %w", tmp, err)
	}

	if err := os.Rename(tmp, dest); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("finalizing %s: %w", dest, err)
	}
	return nil
}

// archSuffix returns the architecture string for download URLs.
func archSuffix() string {
	switch runtime.GOARCH {
	case "arm64":
		return "aarch64"
	default:
		return "x86_64"
	}
}

// subprocess manages a long-running child process with log capture.
type subprocess struct {
	name    string
	cmd     *exec.Cmd
	logFile *os.File
	log     logr.Logger
}

func newSubprocess(name string, log logr.Logger, binPath string, args ...string) *subprocess {
	return &subprocess{
		name: name,
		cmd:  exec.Command(binPath, args...),
		log:  log.WithValues("service", name),
	}
}

func (s *subprocess) start(_ context.Context) error {
	logPath := filepath.Join(LogDir(), s.name+".log")
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("opening log file %s: %w", logPath, err)
	}
	s.logFile = f
	s.cmd.Stdout = f
	s.cmd.Stderr = f

	s.log.Info("starting", "bin", s.cmd.Path, "args", s.cmd.Args[1:])
	if err := s.cmd.Start(); err != nil {
		_ = f.Close()
		return fmt.Errorf("starting %s: %w", s.name, err)
	}

	// Write PID file
	pidPath := filepath.Join(RunDir(), s.name+".pid")
	if err := os.WriteFile(pidPath, []byte(fmt.Sprintf("%d", s.cmd.Process.Pid)), 0644); err != nil {
		s.log.Error(err, "writing PID file")
	}

	s.log.Info("started", "pid", s.cmd.Process.Pid)
	return nil
}

func (s *subprocess) stop(ctx context.Context) error {
	if s.cmd == nil || s.cmd.Process == nil {
		return nil
	}

	s.log.Info("stopping", "pid", s.cmd.Process.Pid)

	if err := s.cmd.Process.Signal(os.Interrupt); err != nil {
		s.log.Error(err, "sending interrupt, falling back to kill")
		_ = s.cmd.Process.Kill()
	}

	done := make(chan error, 1)
	go func() { done <- s.cmd.Wait() }()

	select {
	case <-ctx.Done():
		_ = s.cmd.Process.Kill()
		return fmt.Errorf("timed out stopping %s", s.name)
	case <-time.After(5 * time.Second):
		_ = s.cmd.Process.Kill()
		return fmt.Errorf("timed out stopping %s after 5s", s.name)
	case err := <-done:
		if s.logFile != nil {
			_ = s.logFile.Close()
		}
		pidPath := filepath.Join(RunDir(), s.name+".pid")
		_ = os.Remove(pidPath)
		if err != nil {
			s.log.Info("stopped with error", "error", err)
		} else {
			s.log.Info("stopped cleanly")
		}
		return nil
	}
}
