package embedded

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/go-logr/logr"
)

const (
	temporalVersion = "1.3.0"
	temporalPort    = "17233"
)

// TemporalService manages a local Temporal dev server via the Temporal CLI.
type TemporalService struct {
	proc *subprocess
	log  logr.Logger
}

func NewTemporalService(log logr.Logger) *TemporalService {
	return &TemporalService{log: log.WithValues("service", "temporal")}
}

func (t *TemporalService) Name() string      { return "temporal" }
func (t *TemporalService) IsExternal() bool   { return false }

func (t *TemporalService) Address() string {
	return "localhost:" + temporalPort
}

func (t *TemporalService) Download(ctx context.Context) error {
	dest := filepath.Join(BinDir(), "temporal")
	if _, err := os.Stat(dest); err == nil {
		return nil
	}

	arch := runtime.GOARCH
	osName := runtime.GOOS
	archiveName := fmt.Sprintf("temporal_cli_%s_%s_%s.tar.gz", temporalVersion, osName, arch)
	url := fmt.Sprintf("https://github.com/temporalio/cli/releases/download/v%s/%s",
		temporalVersion, archiveName)

	archivePath := filepath.Join(BinDir(), archiveName)
	if err := downloadBinary(ctx, url, archivePath); err != nil {
		return fmt.Errorf("downloading temporal CLI: %w", err)
	}

	f, err := os.Open(archivePath)
	if err != nil {
		return fmt.Errorf("opening temporal archive: %w", err)
	}
	defer func() { _ = f.Close() }()

	if err := extractTarGz(f, BinDir()); err != nil {
		_ = os.Remove(archivePath)
		return fmt.Errorf("extracting temporal CLI: %w", err)
	}
	_ = os.Remove(archivePath)

	return nil
}

func (t *TemporalService) Start(ctx context.Context) error {
	bin := filepath.Join(BinDir(), "temporal")
	dataDir := ServiceDataDir("temporal")

	t.proc = newSubprocess("temporal", t.log, bin,
		"server", "start-dev",
		"--namespace", "default",
		"--port", temporalPort,
		"--db-filename", filepath.Join(dataDir, "temporal.db"),
		"--log-format", "json",
		"--headless",
	)

	if err := t.proc.start(ctx); err != nil {
		return err
	}

	if err := t.waitReady(ctx); err != nil {
		return fmt.Errorf("waiting for temporal: %w", err)
	}

	t.log.Info("temporal ready", "address", t.Address())
	return nil
}

func (t *TemporalService) Stop(ctx context.Context) error {
	if t.proc == nil {
		return nil
	}
	return t.proc.stop(ctx)
}

func (t *TemporalService) Health(ctx context.Context) error {
	conn, err := net.DialTimeout("tcp", "localhost:"+temporalPort, 2*time.Second)
	if err != nil {
		return fmt.Errorf("temporal not reachable: %w", err)
	}
	_ = conn.Close()
	return nil
}

func (t *TemporalService) waitReady(ctx context.Context) error {
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", "localhost:"+temporalPort, 500*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
	return fmt.Errorf("temporal did not become ready within 30s")
}
