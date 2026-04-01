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
	vaultVersion = "1.21.4"
	vaultPort    = "18200"
)

// VaultService manages an embedded HashiCorp Vault instance running with
// a file storage backend.
type VaultService struct {
	proc *subprocess
	log  logr.Logger
}

func NewVaultService(log logr.Logger) *VaultService {
	return &VaultService{log: log.WithValues("service", "vault")}
}

func (v *VaultService) Name() string      { return "vault" }
func (v *VaultService) IsExternal() bool   { return false }

func (v *VaultService) Address() string {
	return "http://localhost:" + vaultPort
}

func (v *VaultService) Download(ctx context.Context) error {
	dest := filepath.Join(BinDir(), "vault")
	if _, err := os.Stat(dest); err == nil {
		return nil
	}

	arch := runtime.GOARCH
	osName := runtime.GOOS
	url := fmt.Sprintf("https://releases.hashicorp.com/vault/%s/vault_%s_%s_%s.zip",
		vaultVersion, vaultVersion, osName, arch)

	v.log.Info("downloading vault", "version", vaultVersion, "url", url)

	archivePath := filepath.Join(BinDir(), "vault-"+vaultVersion+".zip")
	if err := downloadBinary(ctx, url, archivePath); err != nil {
		return fmt.Errorf("downloading vault: %w", err)
	}

	if err := extractVaultBinary(archivePath, dest); err != nil {
		_ = os.Remove(archivePath)
		return fmt.Errorf("extracting vault: %w", err)
	}
	_ = os.Remove(archivePath)

	return nil
}

func extractVaultBinary(zipPath, dest string) error {
	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		return fmt.Errorf("opening zip: %w", err)
	}
	defer func() { _ = zr.Close() }()

	for _, f := range zr.File {
		if filepath.Base(f.Name) != "vault" {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return fmt.Errorf("opening vault in zip: %w", err)
		}
		defer func() { _ = rc.Close() }()

		out, err := os.OpenFile(dest, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
		if err != nil {
			return fmt.Errorf("creating %s: %w", dest, err)
		}
		defer func() { _ = out.Close() }()

		if _, err := io.Copy(out, rc); err != nil {
			return fmt.Errorf("writing vault binary: %w", err)
		}
		return nil
	}
	return fmt.Errorf("vault binary not found in zip")
}

func (v *VaultService) Start(ctx context.Context) error {
	bin := filepath.Join(BinDir(), "vault")

	// Dev mode: in-memory storage, auto-unsealed, root token preset.
	// Data does not persist across restarts — acceptable for local mode.
	v.proc = newSubprocess("vault", v.log, bin,
		"server",
		"-dev",
		"-dev-listen-address", "127.0.0.1:"+vaultPort,
		"-dev-root-token-id", "agentcage-dev-token",
	)
	v.proc.cmd.Env = append(os.Environ(),
		"VAULT_DEV_ROOT_TOKEN_ID=agentcage-dev-token",
	)

	if err := v.proc.start(ctx); err != nil {
		return err
	}

	if err := v.waitReady(ctx); err != nil {
		return fmt.Errorf("waiting for vault: %w", err)
	}

	v.log.Info("vault ready", "address", v.Address())
	return nil
}

func (v *VaultService) Stop(ctx context.Context) error {
	if v.proc == nil {
		return nil
	}
	return v.proc.stop(ctx)
}

func (v *VaultService) Health(ctx context.Context) error {
	conn, err := net.DialTimeout("tcp", "localhost:"+vaultPort, 2*time.Second)
	if err != nil {
		return fmt.Errorf("vault not reachable: %w", err)
	}
	_ = conn.Close()
	return nil
}

func (v *VaultService) waitReady(ctx context.Context) error {
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", "localhost:"+vaultPort, 500*time.Millisecond)
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
	return fmt.Errorf("vault did not become ready within 15s")
}
