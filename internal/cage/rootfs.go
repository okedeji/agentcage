package cage

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/go-logr/logr"

	"github.com/okedeji/agentcage/internal/cagefile"
)

// Env holds the environment variables injected into a cage VM at
// boot. cage-init reads these from /etc/agentcage/cage.json.
type Env struct {
	CageID       string          `json:"cage_id"`
	AssessmentID string          `json:"assessment_id"`
	CageType     string          `json:"cage_type"`
	Entrypoint   string          `json:"entrypoint"`
	Objective    string          `json:"objective,omitempty"`
	LLMEndpoint  string          `json:"llm_endpoint,omitempty"`
	NATSAddr     string          `json:"nats_addr,omitempty"`
	ScopeHosts   []string        `json:"scope_hosts"`
	ScopePorts   []string        `json:"scope_ports,omitempty"`
	ScopePaths   []string        `json:"scope_paths,omitempty"`
	TokenBudget  int64           `json:"token_budget,omitempty"`
	ProxyMode    string          `json:"proxy_mode"`
	VulnClass    string          `json:"vuln_class,omitempty"`
	Guidance json.RawMessage `json:"guidance,omitempty"`
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
func (b *RootfsBuilder) Assemble(ctx context.Context, cageID string, bundle *cagefile.BundleManifest, bundleFilesDir string, env Env) (rootfsPath string, retErr error) {
	if err := cagefile.CheckCompatibility(bundle, b.version); err != nil {
		return "", fmt.Errorf("cage %s: %w", cageID, err)
	}

	// Verify bundle integrity FIRST. Before copying the base rootfs,
	// before mounting, before any install commands. A tampered bundle
	// that gets past this check can't execute install hooks via
	// chroot, because there's nothing to chroot into yet.
	if bundle.FilesHash != "" {
		hash, hashErr := cagefile.HashDir(bundleFilesDir)
		if hashErr != nil {
			return "", fmt.Errorf("hashing agent files for verification: %w", hashErr)
		}
		if "sha256:"+hash != bundle.FilesHash {
			return "", fmt.Errorf("cage %s: agent files hash mismatch, bundle may be tampered (expected %s, got sha256:%s)", cageID, bundle.FilesHash, hash)
		}
	}

	rootfsPath = filepath.Join(b.workDir, cageID+".ext4")

	// Reject concurrent Assemble for the same cage ID. Cage IDs are
	// UUIDs, so collision means an upstream idempotency bug;
	// clobbering an in-use rootfs file would corrupt the running cage.
	// SweepStale runs at startup so legitimate post-crash leftovers
	// don't trip this.
	if _, err := os.Stat(rootfsPath); err == nil {
		return "", fmt.Errorf("cage %s: rootfs %s already exists, concurrent Assemble or stale state", cageID, rootfsPath)
	}

	// Copy base rootfs. cp --reflink=auto gives copy-on-write on
	// filesystems that support it (btrfs, xfs); plain cp otherwise.
	if err := copyRootfs(ctx, b.baseRootfsPath, rootfsPath); err != nil {
		return "", fmt.Errorf("copying base rootfs: %w", err)
	}

	// If anything below fails, the partially-built rootfs file is
	// junk. Remove it so the work directory doesn't accumulate dead
	// files across failed assemblies.
	defer func() {
		if retErr != nil {
			_ = os.Remove(rootfsPath)
		}
	}()

	// Mount the rootfs, inject files, unmount. The deferred cleanup runs
	// unmount first; only on a clean unmount do we RemoveAll the mount
	// dir, so a failed unmount leaves the directory in place where the
	// SweepStale path on next startup will reclaim it. Removing a
	// still-mounted directory would either silently fail or, worse, leak
	// an orphan mount only reapable by reboot.
	mountDir := filepath.Join(b.workDir, "mnt-"+cageID)
	if err := os.MkdirAll(mountDir, 0755); err != nil {
		return "", fmt.Errorf("creating mount directory: %w", err)
	}

	if err := mountExt4(ctx, rootfsPath, mountDir); err != nil {
		_ = os.RemoveAll(mountDir)
		return "", fmt.Errorf("mounting rootfs: %w", err)
	}
	defer func() {
		if err := unmountExt4(ctx, mountDir); err != nil {
			// Leave the mount dir for SweepStale to reclaim later.
			return
		}
		_ = os.RemoveAll(mountDir)
	}()

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

// Cleanup removes the assembled rootfs and any mount directory left
// behind for the cage. Assemble's deferred unmount normally handles
// the mount dir, but a panic or OS-level kill can leave one orphaned;
// this gives teardown a second chance to reclaim it.
func (b *RootfsBuilder) Cleanup(cageID string) error {
	mountDir := filepath.Join(b.workDir, "mnt-"+cageID)
	if _, err := os.Stat(mountDir); err == nil {
		// Try to unmount in case the orphan is still mounted; ignore the
		// error since the dir may simply be empty.
		_ = unmountExt4(context.Background(), mountDir)
		_ = os.RemoveAll(mountDir)
	}

	rootfsPath := filepath.Join(b.workDir, cageID+".ext4")
	if err := os.Remove(rootfsPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("removing cage %s rootfs: %w", cageID, err)
	}
	return nil
}

// SweepStale removes leftover .ext4 files and mnt-* directories from a
// previous orchestrator run that did not shut down cleanly. Safe to call at
// startup before any cages are assembled. Mount directories are unmounted
// first if still mounted.
func (b *RootfsBuilder) SweepStale(ctx context.Context, log logr.Logger) error {
	entries, err := os.ReadDir(b.workDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("listing rootfs work dir %s: %w", b.workDir, err)
	}

	var sweptFiles, sweptMounts int
	for _, e := range entries {
		name := e.Name()
		full := filepath.Join(b.workDir, name)

		if e.IsDir() && strings.HasPrefix(name, "mnt-") {
			// Try to unmount; ignore failure (probably not mounted) and
			// then remove the directory.
			_ = unmountExt4(ctx, full)
			_ = os.RemoveAll(full)
			sweptMounts++
			continue
		}

		if !e.IsDir() && strings.HasSuffix(name, ".ext4") {
			_ = os.Remove(full)
			sweptFiles++
		}
	}

	if sweptFiles > 0 || sweptMounts > 0 {
		log.Info("swept stale rootfs state",
			"dir", b.workDir, "files", sweptFiles, "mount_dirs", sweptMounts)
	}
	return nil
}

// copyRootfs copies the base rootfs image to a per-cage destination,
// using cp --reflink=auto where supported so the copy is
// near-zero-cost. Falls back to plain cp only on flag-not-supported
// errors. Real failures (ENOSPC, EPERM, missing source) propagate
// immediately instead of being masked by an identical second attempt.
func copyRootfs(ctx context.Context, src, dst string) error {
	cmd := exec.CommandContext(ctx, "cp", "--reflink=auto", src, dst)
	out, err := cmd.CombinedOutput()
	if err == nil {
		return nil
	}

	// BSD cp (macOS dev) does not understand --reflink. Recognize the
	// classic flag-error patterns and fall back. Anything else is a real
	// failure and is reported as-is.
	outStr := string(out)
	if !strings.Contains(outStr, "--reflink") && !strings.Contains(outStr, "illegal option") && !strings.Contains(outStr, "unrecognized option") {
		return fmt.Errorf("cp %s %s: %w\n%s", src, dst, err, outStr)
	}

	cmd2 := exec.CommandContext(ctx, "cp", src, dst)
	if out2, err2 := cmd2.CombinedOutput(); err2 != nil {
		return fmt.Errorf("cp (no-reflink) %s %s: %w\n%s", src, dst, err2, out2)
	}
	return nil
}

// mountExt4 mounts a cage rootfs image with nosuid,nodev. Without
// those flags, a malicious bundle could ship a setuid binary or
// device node and have it honored at host privilege during the
// assembly chroot. noexec is intentionally not set; the install
// steps (apk, pip, npm) need to exec from inside the chroot.
func mountExt4(ctx context.Context, imgPath, mountPoint string) error {
	cmd := exec.CommandContext(ctx, "mount", "-o", "loop,nosuid,nodev", imgPath, mountPoint)
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
		return fmt.Errorf("apk add %s: %w\n%s", strings.Join(packages, ","), err, out)
	}
	return nil
}

func installPipDeps(ctx context.Context, mountDir string, deps []string) error {
	args := append([]string{mountDir, "pip3", "install", "--no-cache-dir"}, deps...)
	cmd := exec.CommandContext(ctx, "chroot", args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("pip install %s: %w\n%s", strings.Join(deps, ","), err, out)
	}
	return nil
}

func installNpmDeps(ctx context.Context, mountDir string, deps []string) error {
	args := append([]string{mountDir, "npm", "install", "-g"}, deps...)
	cmd := exec.CommandContext(ctx, "chroot", args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("npm install %s: %w\n%s", strings.Join(deps, ","), err, out)
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
