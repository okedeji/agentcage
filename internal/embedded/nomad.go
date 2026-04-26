package embedded

import (
	"archive/zip"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/go-logr/logr"
)

const (
	nomadVersion = "2.0.0"
	nomadPort    = "14646"
)

func NomadPort() string { return nomadPort }

// NomadService manages an embedded HashiCorp Nomad agent running in
// dev mode (combined server + client). Suitable for single-host and
// test deployments where the operator does not run a separate cluster.
type NomadService struct {
	proc     *subprocess
	bindAddr string
	log      logr.Logger
}

func NewNomadService(log logr.Logger) *NomadService {
	return &NomadService{bindAddr: "127.0.0.1", log: log.WithValues("service", "nomad")}
}

func NewNomadServiceWithBind(log logr.Logger, bindAddr string) *NomadService {
	return &NomadService{bindAddr: bindAddr, log: log.WithValues("service", "nomad")}
}

func (n *NomadService) Name() string     { return "nomad" }
func (n *NomadService) IsExternal() bool { return false }

func (n *NomadService) Address() string {
	return "http://localhost:" + nomadPort
}

func (n *NomadService) Download(ctx context.Context) error {
	dest := filepath.Join(BinDir(), "nomad")
	if _, err := os.Stat(dest); err == nil {
		return nil
	}

	arch := runtime.GOARCH
	osName := runtime.GOOS
	url := fmt.Sprintf("https://releases.hashicorp.com/nomad/%s/nomad_%s_%s_%s.zip",
		nomadVersion, nomadVersion, osName, arch)

	n.log.Info("downloading nomad", "version", nomadVersion, "url", url)

	archivePath := filepath.Join(BinDir(), "nomad-"+nomadVersion+".zip")
	if err := downloadBinary(ctx, url, archivePath); err != nil {
		return fmt.Errorf("downloading nomad: %w", err)
	}

	if err := extractNomadBinary(archivePath, dest); err != nil {
		_ = os.Remove(archivePath)
		return fmt.Errorf("extracting nomad: %w", err)
	}
	_ = os.Remove(archivePath)

	return nil
}

func extractNomadBinary(zipPath, dest string) error {
	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		return fmt.Errorf("opening zip: %w", err)
	}
	defer func() { _ = zr.Close() }()

	for _, f := range zr.File {
		if filepath.Base(f.Name) != "nomad" {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return fmt.Errorf("opening nomad in zip: %w", err)
		}
		defer func() { _ = rc.Close() }()

		out, err := os.OpenFile(dest, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
		if err != nil {
			return fmt.Errorf("creating %s: %w", dest, err)
		}
		defer func() { _ = out.Close() }()

		if _, err := io.Copy(out, rc); err != nil {
			return fmt.Errorf("writing nomad binary: %w", err)
		}
		return nil
	}
	return fmt.Errorf("nomad binary not found in zip")
}

func (n *NomadService) Start(ctx context.Context) error {
	bin := filepath.Join(BinDir(), "nomad")
	dataDir := filepath.Join(DataDir(), "nomad")
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return fmt.Errorf("creating nomad data dir: %w", err)
	}

	// Nomad doesn't accept -http-port as a CLI flag. Write a
	// minimal config file to override the default 4646 port so
	// embedded Nomad doesn't conflict with an existing installation.
	cfgPath := filepath.Join(dataDir, "embedded.hcl")
	cfgContent := fmt.Sprintf(`
bind_addr = "%s"
ports {
  http = %s
}
`, n.bindAddr, nomadPort)
	if err := os.WriteFile(cfgPath, []byte(cfgContent), 0644); err != nil {
		return fmt.Errorf("writing nomad config: %w", err)
	}

	n.proc = newSubprocess("nomad", n.log, bin,
		"agent",
		"-dev",
		"-config", cfgPath,
		"-data-dir", dataDir,
	)

	if err := n.proc.start(ctx); err != nil {
		return err
	}

	if err := n.waitReady(ctx); err != nil {
		return fmt.Errorf("waiting for nomad: %w", err)
	}

	n.log.Info("nomad ready", "address", n.Address())
	return nil
}

func (n *NomadService) Stop(ctx context.Context) error {
	if n.proc == nil {
		return nil
	}
	return n.proc.stop(ctx)
}

func (n *NomadService) Health(ctx context.Context) error {
	conn, err := net.DialTimeout("tcp", "localhost:"+nomadPort, 2*time.Second)
	if err != nil {
		return fmt.Errorf("nomad not reachable: %w", err)
	}
	_ = conn.Close()
	return nil
}

func (n *NomadService) waitReady(ctx context.Context) error {
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", "localhost:"+nomadPort, 500*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(300 * time.Millisecond):
		}
	}
	return fmt.Errorf("nomad did not become ready within 30s")
}
