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
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/go-logr/logr"

	"github.com/okedeji/agentcage/internal/config"
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
func DataDir() string {
	return config.HomeDir()
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
// DownloadFile downloads a URL to a local path. Used by host-init
// for downloading the cage rootfs.
func DownloadFile(ctx context.Context, url, dest string) error {
	return downloadBinary(ctx, url, dest)
}

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

	var reader io.Reader = resp.Body
	if resp.ContentLength > 0 {
		reader = &progressLogger{
			reader: resp.Body,
			total:  resp.ContentLength,
			name:   filepath.Base(dest),
		}
	}

	written, err := io.Copy(f, reader)
	if err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("writing %s: %w", dest, err)
	}
	if resp.ContentLength > 0 && written != resp.ContentLength {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("downloading %s: expected %d bytes, got %d (truncated)", filepath.Base(dest), resp.ContentLength, written)
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

type progressLogger struct {
	reader  io.Reader
	total   int64
	current int64
	name    string
	lastPct int
}

func (p *progressLogger) Read(buf []byte) (int, error) {
	n, err := p.reader.Read(buf)
	p.current += int64(n)
	pct := int(p.current * 100 / p.total)
	if pct >= p.lastPct+10 {
		p.lastPct = pct - (pct % 10)
		fmt.Fprintf(os.Stderr, "{\"level\":\"info\",\"msg\":\"progress\",\"service\":\"%s\",\"percent\":%d}\n", p.name, pct)
	}
	return n, err
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

// isAlreadyRunning checks for a stale PID file and returns true if the
// process is still alive. Cleans up the PID file if the process is dead.
func (s *subprocess) isAlreadyRunning() bool {
	pidPath := filepath.Join(RunDir(), s.name+".pid")
	data, err := os.ReadFile(pidPath)
	if err != nil {
		return false
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		_ = os.Remove(pidPath)
		return false
	}
	// Signal 0 tests whether the process exists without killing it.
	if err := syscall.Kill(pid, 0); err != nil {
		_ = os.Remove(pidPath)
		return false
	}
	s.log.Info("already running", "pid", pid)
	return true
}

func (s *subprocess) start(_ context.Context) error {
	if s.isAlreadyRunning() {
		return fmt.Errorf("%s is already running (see %s/%s.pid)", s.name, RunDir(), s.name)
	}

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
