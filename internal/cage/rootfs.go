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
	baseRootfsPath string
	workDir        string
	version        string
}

func NewRootfsBuilder(baseRootfsPath, workDir, version string) *RootfsBuilder {
	return &RootfsBuilder{
		baseRootfsPath: baseRootfsPath,
		workDir:        workDir,
		version:        version,
	}
}

// Assemble creates a rootfs for a specific cage by:
// 1. Copying the base rootfs (copy-on-write where possible)
// 2. Mounting it and injecting the agent files from the .cage bundle
// 3. Writing cage config as /etc/agentcage/cage.json
//
// Returns the path to the assembled rootfs.
func (b *RootfsBuilder) Assemble(ctx context.Context, cageID string, bundle *cagefile.BundleManifest, bundleFilesDir string, env CageEnv) (string, error) {
	if err := cagefile.CheckCompatibility(bundle, b.version); err != nil {
		return "", fmt.Errorf("cage %s: %w", cageID, err)
	}

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

	// Install user-requested Alpine packages
	if len(bundle.Packages) > 0 {
		if err := installPackages(ctx, mountDir, bundle.Packages); err != nil {
			return "", fmt.Errorf("installing packages: %w", err)
		}
	}

	// Install language-specific dependencies
	if len(bundle.PipDeps) > 0 {
		if err := installPipDeps(ctx, mountDir, bundle.PipDeps); err != nil {
			return "", fmt.Errorf("installing pip dependencies: %w", err)
		}
	}
	if len(bundle.NpmDeps) > 0 {
		if err := installNpmDeps(ctx, mountDir, bundle.NpmDeps); err != nil {
			return "", fmt.Errorf("installing npm dependencies: %w", err)
		}
	}
	if len(bundle.GoDeps) > 0 {
		if err := installGoDeps(ctx, mountDir, bundle.GoDeps); err != nil {
			return "", fmt.Errorf("installing go dependencies: %w", err)
		}
	}

	// Verify bundle integrity before injecting into rootfs
	if bundle.FilesHash != "" {
		hash, hashErr := cagefile.HashDir(bundleFilesDir)
		if hashErr != nil {
			return "", fmt.Errorf("hashing agent files for verification: %w", hashErr)
		}
		if "sha256:"+hash != bundle.FilesHash {
			return "", fmt.Errorf("cage %s: agent files hash mismatch — bundle may be tampered (expected %s, got sha256:%s)", cageID, bundle.FilesHash, hash)
		}
	}

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

func installPackages(ctx context.Context, mountDir string, packages []string) error {
	args := append([]string{mountDir, "apk", "add", "--no-cache"}, packages...)
	cmd := exec.CommandContext(ctx, "chroot", args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("apk add %v: %w\n%s", packages, err, out)
	}
	return nil
}

func installPipDeps(ctx context.Context, mountDir string, deps []string) error {
	args := append([]string{mountDir, "pip3", "install", "--no-cache-dir"}, deps...)
	cmd := exec.CommandContext(ctx, "chroot", args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("pip install %v: %w\n%s", deps, err, out)
	}
	return nil
}

func installNpmDeps(ctx context.Context, mountDir string, deps []string) error {
	args := append([]string{mountDir, "npm", "install", "-g"}, deps...)
	cmd := exec.CommandContext(ctx, "chroot", args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("npm install %v: %w\n%s", deps, err, out)
	}
	return nil
}

func installGoDeps(ctx context.Context, mountDir string, deps []string) error {
	for _, dep := range deps {
		cmd := exec.CommandContext(ctx, "chroot", mountDir, "go", "install", dep)
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("go install %s: %w\n%s", dep, err, out)
		}
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
