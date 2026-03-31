package cage

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/okedeji/agentcage/internal/cagefile"
)

// CageEnv holds the environment variables injected into a cage VM at boot.
// cage-init reads these from /etc/agentcage/cage.json.
type CageEnv struct {
	CageID       string   `json:"cage_id"`
	AssessmentID string   `json:"assessment_id"`
	CageType     string   `json:"cage_type"`
	Entrypoint   string   `json:"entrypoint"`
	Objective    string   `json:"objective,omitempty"`
	LLMEndpoint  string   `json:"llm_endpoint,omitempty"`
	NATSAddr     string   `json:"nats_addr,omitempty"`
	ScopeHosts   []string `json:"scope_hosts"`
	ScopePorts   []string `json:"scope_ports,omitempty"`
	ScopePaths   []string `json:"scope_paths,omitempty"`
	TokenBudget  int64    `json:"token_budget,omitempty"`
	ProxyMode    string   `json:"proxy_mode"`
	VulnClass    string   `json:"vuln_class,omitempty"`
}

// RootfsBuilder assembles a Firecracker-bootable ext4 rootfs from a base
// image and a .cage bundle.
type RootfsBuilder struct {
	baseRootfsPath string // path to the base ext4 image
	workDir        string // directory for assembled rootfs copies
}

func NewRootfsBuilder(baseRootfsPath, workDir string) *RootfsBuilder {
	return &RootfsBuilder{
		baseRootfsPath: baseRootfsPath,
		workDir:        workDir,
	}
}

// Assemble creates a rootfs for a specific cage by:
// 1. Copying the base rootfs (copy-on-write where possible)
// 2. Mounting it and injecting the agent files from the .cage bundle
// 3. Writing cage config as /etc/agentcage/cage.json
//
// Returns the path to the assembled rootfs.
func (b *RootfsBuilder) Assemble(ctx context.Context, cageID string, bundle *cagefile.BundleManifest, bundleFilesDir string, env CageEnv) (string, error) {
	rootfsPath := filepath.Join(b.workDir, cageID+".ext4")

	// Copy base rootfs — use cp --reflink=auto for copy-on-write on
	// filesystems that support it (btrfs, xfs), falls back to full copy.
	if err := copyRootfs(ctx, b.baseRootfsPath, rootfsPath); err != nil {
		return "", fmt.Errorf("copying base rootfs: %w", err)
	}

	// Mount the rootfs, inject files, unmount
	mountDir := filepath.Join(b.workDir, "mnt-"+cageID)
	if err := os.MkdirAll(mountDir, 0755); err != nil {
		return "", fmt.Errorf("creating mount directory: %w", err)
	}
	defer func() { _ = os.RemoveAll(mountDir) }()

	if err := mountExt4(ctx, rootfsPath, mountDir); err != nil {
		return "", fmt.Errorf("mounting rootfs: %w", err)
	}
	defer unmountExt4(ctx, mountDir) //nolint:errcheck

	// Inject agent files
	agentDir := filepath.Join(mountDir, "opt", "agent")
	if err := os.MkdirAll(agentDir, 0755); err != nil {
		return "", fmt.Errorf("creating agent directory: %w", err)
	}
	if err := copyDir(ctx, bundleFilesDir, agentDir); err != nil {
		return "", fmt.Errorf("injecting agent files: %w", err)
	}

	// Write cage config
	configDir := filepath.Join(mountDir, "etc", "agentcage")
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return "", fmt.Errorf("creating config directory: %w", err)
	}
	envJSON, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshaling cage env: %w", err)
	}
	if err := os.WriteFile(filepath.Join(configDir, "cage.json"), envJSON, 0644); err != nil {
		return "", fmt.Errorf("writing cage.json: %w", err)
	}

	return rootfsPath, nil
}

// Cleanup removes the assembled rootfs for a cage.
func (b *RootfsBuilder) Cleanup(cageID string) error {
	rootfsPath := filepath.Join(b.workDir, cageID+".ext4")
	return os.Remove(rootfsPath)
}

func copyRootfs(ctx context.Context, src, dst string) error {
	cmd := exec.CommandContext(ctx, "cp", "--reflink=auto", src, dst)
	if out, err := cmd.CombinedOutput(); err != nil {
		// Fall back to regular copy if --reflink is not supported
		cmd2 := exec.CommandContext(ctx, "cp", src, dst)
		if out2, err2 := cmd2.CombinedOutput(); err2 != nil {
			return fmt.Errorf("cp %s %s: %w\n%s\n%s", src, dst, err2, out, out2)
		}
	}
	return nil
}

func mountExt4(ctx context.Context, imgPath, mountPoint string) error {
	cmd := exec.CommandContext(ctx, "mount", "-o", "loop", imgPath, mountPoint)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("mount %s: %w\n%s", imgPath, err, out)
	}
	return nil
}

func unmountExt4(ctx context.Context, mountPoint string) error {
	cmd := exec.CommandContext(ctx, "umount", mountPoint)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("umount %s: %w\n%s", mountPoint, err, out)
	}
	return nil
}

func copyDir(ctx context.Context, src, dst string) error {
	cmd := exec.CommandContext(ctx, "cp", "-a", src+"/.", dst)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("copying %s to %s: %w\n%s", src, dst, err, out)
	}
	return nil
}
