package embedded

import (
	"archive/zip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"

	"github.com/go-logr/logr"
)

const (
	vaultVersion = "1.21.4"
	vaultPort    = "18200"
)

// VaultService manages an embedded HashiCorp Vault instance with
// file storage so secrets persist across restarts.
type VaultService struct {
	proc      *subprocess
	log       logr.Logger
	rootToken string
}

func NewVaultService(log logr.Logger) *VaultService {
	return &VaultService{log: log.WithValues("service", "vault")}
}

func (v *VaultService) Name() string      { return "vault" }
func (v *VaultService) IsExternal() bool   { return false }

func (v *VaultService) Address() string {
	return "http://localhost:" + vaultPort
}

// RootToken returns the root token generated during init. Set after
// Start completes.
func (v *VaultService) RootToken() string {
	return v.rootToken
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
	if err := downloadBinaryWithLog(ctx, url, archivePath, v.log); err != nil {
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

	tmp := dest + ".tmp"
	for _, f := range zr.File {
		if filepath.Base(f.Name) != "vault" {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return fmt.Errorf("opening vault in zip: %w", err)
		}

		out, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
		if err != nil {
			_ = rc.Close()
			return fmt.Errorf("creating %s: %w", tmp, err)
		}

		_, copyErr := io.Copy(out, rc)
		_ = rc.Close()
		_ = out.Close()
		if copyErr != nil {
			_ = os.Remove(tmp)
			return fmt.Errorf("writing vault binary: %w", copyErr)
		}
		if err := os.Rename(tmp, dest); err != nil {
			_ = os.Remove(tmp)
			return fmt.Errorf("finalizing vault binary: %w", err)
		}
		return nil
	}
	return fmt.Errorf("vault binary not found in zip")
}

func (v *VaultService) Start(ctx context.Context) error {
	bin := filepath.Join(BinDir(), "vault")
	dataDir := ServiceDataDir("vault")
	storageDir := filepath.Join(dataDir, "storage")
	if err := os.MkdirAll(storageDir, 0700); err != nil {
		return fmt.Errorf("creating vault storage dir: %w", err)
	}

	// File storage so secrets persist across restarts. Init and
	// unseal are automatic using a single key share stored locally.
	cfgPath := filepath.Join(dataDir, "vault.hcl")
	cfgContent := fmt.Sprintf(`
disable_mlock = true
ui            = false
api_addr      = "http://127.0.0.1:%s"

listener "tcp" {
  address     = "127.0.0.1:%s"
  tls_disable = 1
}

storage "file" {
  path = "%s"
}
`, vaultPort, vaultPort, storageDir)
	if err := os.WriteFile(cfgPath, []byte(cfgContent), 0600); err != nil {
		return fmt.Errorf("writing vault config: %w", err)
	}

	v.proc = newSubprocess("vault", v.log, bin, "server", "-config", cfgPath)
	v.proc.cmd.Env = append(os.Environ(), "VAULT_ADDR=http://127.0.0.1:"+vaultPort)

	if err := v.proc.start(ctx); err != nil {
		return err
	}

	if err := v.waitReady(ctx); err != nil {
		return fmt.Errorf("waiting for vault: %w", err)
	}

	if err := v.initAndUnseal(ctx, bin, dataDir); err != nil {
		return fmt.Errorf("vault init/unseal: %w", err)
	}

	v.log.Info("vault ready", "address", v.Address(), "storage", storageDir)
	return nil
}

func (v *VaultService) initAndUnseal(ctx context.Context, bin, dataDir string) error {
	keyFile := filepath.Join(dataDir, "init-keys.json")
	env := append(os.Environ(), "VAULT_ADDR="+v.Address())

	if _, err := os.Stat(keyFile); os.IsNotExist(err) {
		initCmd := exec.CommandContext(ctx, bin, "operator", "init",
			"-key-shares=1", "-key-threshold=1", "-format=json")
		initCmd.Env = env
		out, err := initCmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("vault operator init: %w\n%s", err, out)
		}
		if err := os.WriteFile(keyFile, out, 0600); err != nil {
			return fmt.Errorf("saving vault init keys: %w", err)
		}
		v.log.Info("vault initialized (first run)")
	}

	data, err := os.ReadFile(keyFile)
	if err != nil {
		return fmt.Errorf("reading vault init keys: %w", err)
	}

	var initResult struct {
		UnsealKeysB64 []string `json:"unseal_keys_b64"`
		RootToken     string   `json:"root_token"`
	}
	if err := json.Unmarshal(data, &initResult); err != nil {
		return fmt.Errorf("parsing vault init keys: %w", err)
	}
	if len(initResult.UnsealKeysB64) == 0 {
		return fmt.Errorf("no unseal keys in %s", keyFile)
	}
	v.rootToken = initResult.RootToken

	unsealCmd := exec.CommandContext(ctx, bin, "operator", "unseal", initResult.UnsealKeysB64[0])
	unsealCmd.Env = env
	if out, err := unsealCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("vault unseal: %w\n%s", err, out)
	}

	// Enable KV v2 secrets engine on first run.
	kvCmd := exec.CommandContext(ctx, bin, "secrets", "enable", "-path=secret", "kv-v2")
	kvCmd.Env = append(env, "VAULT_TOKEN="+v.rootToken)
	_, _ = kvCmd.CombinedOutput()

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
