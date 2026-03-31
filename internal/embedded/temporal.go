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
	temporalVersion = "0.3.0"
	temporalPort    = "17233"
)

// TemporalService manages an embedded Temporalite instance.
// Temporalite is a single-binary, SQLite-backed Temporal server designed
// for development and lightweight production use.
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
	dest := filepath.Join(BinDir(), "temporalite")
	if _, err := os.Stat(dest); err == nil {
		return nil
	}

	arch := runtime.GOARCH
	osName := runtime.GOOS
	url := fmt.Sprintf("https://github.com/temporalio/temporalite/releases/download/v%s/temporalite_%s_%s_%s",
		temporalVersion, temporalVersion, osName, arch)

	return downloadBinary(ctx, url, dest)
}

func (t *TemporalService) Start(ctx context.Context) error {
	bin := filepath.Join(BinDir(), "temporalite")
	dataDir := ServiceDataDir("temporal")

	t.proc = newSubprocess("temporal", t.log, bin,
		"start",
		"--ephemeral",
		"--namespace", "default",
		"--port", temporalPort,
		"--db-filename", filepath.Join(dataDir, "temporal.db"),
		"--log-format", "json",
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
	conn.Close()
	return nil
}

func (t *TemporalService) waitReady(ctx context.Context) error {
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", "localhost:"+temporalPort, 500*time.Millisecond)
		if err == nil {
			conn.Close()
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
