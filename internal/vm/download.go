package vm

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"

	"github.com/schollz/progressbar/v3"
)

// knownChecksums maps asset filenames to expected SHA-256 hex
// digests. Populate at release time. When empty, verification is
// skipped with a warning; only acceptable during development.
var knownChecksums = map[string]string{
	// "vmlinux-6.1-arm64":          "sha256-hex-here",
	// "vmlinux-6.1-amd64":          "sha256-hex-here",
	// "rootfs-3.19-arm64.img":      "sha256-hex-here",
	// "rootfs-3.19-amd64.img":      "sha256-hex-here",
	// "agentcage-linux-arm64":      "sha256-hex-here",
	// "agentcage-linux-amd64":      "sha256-hex-here",
}

// EnsureAssets downloads the kernel, rootfs, and linux agentcage
// binary if not already cached. Downloads run sequentially so each
// progress bar gets a clean terminal line.
func EnsureAssets(ctx context.Context, agentcageVersion string) error {
	if err := os.MkdirAll(Dir(), 0755); err != nil {
		return fmt.Errorf("creating VM directory: %w", err)
	}

	needed := 0
	for _, p := range []string{KernelPath(), RootfsPath(), LinuxBinaryPath()} {
		if _, err := os.Stat(p); err != nil {
			needed++
		}
	}
	if needed == 0 {
		fmt.Println("     All assets cached")
		return nil
	}

	if err := ensureKernel(ctx, agentcageVersion); err != nil {
		return fmt.Errorf("ensuring kernel: %w", err)
	}
	if err := ensureRootfs(ctx, agentcageVersion); err != nil {
		return fmt.Errorf("ensuring rootfs: %w", err)
	}
	if err := ensureLinuxBinary(ctx, agentcageVersion); err != nil {
		return fmt.Errorf("ensuring linux binary: %w", err)
	}
	return nil
}

func ensureKernel(ctx context.Context, version string) error {
	dest := KernelPath()
	if _, err := os.Stat(dest); err == nil {
		return nil
	}

	// Custom kernel built with all virtio drivers and virtiofs as
	// built-in (=y). No modules, no initramfs needed.
	arch := runtime.GOARCH
	url := fmt.Sprintf(
		"https://github.com/okedeji/agentcage/releases/download/v%s/vmlinux-%s-%s",
		version, kernelVersion, arch,
	)
	if err := download(ctx, url, dest, ""); err != nil {
		return err
	}
	return verifyChecksum(dest)
}

func ensureRootfs(ctx context.Context, version string) error {
	dest := RootfsPath()
	if _, err := os.Stat(dest); err == nil {
		return nil
	}

	arch := runtime.GOARCH
	url := fmt.Sprintf(
		"https://github.com/okedeji/agentcage/releases/download/v%s/rootfs-%s.img",
		version, arch,
	)
	if err := download(ctx, url, dest, ""); err != nil {
		return err
	}
	return verifyChecksum(dest)
}

func ensureLinuxBinary(ctx context.Context, version string) error {
	dest := LinuxBinaryPath()
	if _, err := os.Stat(dest); err == nil {
		return nil
	}

	arch := runtime.GOARCH
	url := fmt.Sprintf(
		"https://github.com/okedeji/agentcage/releases/download/v%s/agentcage-linux-%s",
		version, arch,
	)
	if err := download(ctx, url, dest, ""); err != nil {
		return err
	}
	if err := verifyChecksum(dest); err != nil {
		return err
	}
	return os.Chmod(dest, 0755)
}

// verifyChecksum computes the SHA-256 of the file at path and compares it
// against knownChecksums. If no checksum is registered for the file, verification
// is skipped (pre-release development). On mismatch the file is deleted.
func verifyChecksum(path string) error {
	name := filepath.Base(path)
	expected, ok := knownChecksums[name]
	if !ok {
		fmt.Fprintf(os.Stderr, "warning: no checksum for %s, skipping verification (pre-release)\n", name)
		return nil
	}

	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("opening %s for checksum: %w", name, err)
	}
	defer func() { _ = f.Close() }()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return fmt.Errorf("computing checksum for %s: %w", name, err)
	}

	got := hex.EncodeToString(h.Sum(nil))
	if subtle.ConstantTimeCompare([]byte(got), []byte(expected)) != 1 {
		_ = os.Remove(path)
		return fmt.Errorf("checksum mismatch for %s: expected %s, got %s (file deleted)", name, expected, got)
	}
	return nil
}

// download fetches url to dest with a progress bar. displayName overrides
// the filename shown in the bar; empty uses the dest basename.
func download(ctx context.Context, url, dest, displayName string) error {
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
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("creating %s: %w", tmp, err)
	}

	name := displayName
	if name == "" {
		name = filepath.Base(dest)
	}

	var reader io.Reader = resp.Body
	if resp.ContentLength > 0 {
		bar := progressbar.DefaultBytes(resp.ContentLength, "     "+name)
		reader = io.TeeReader(resp.Body, bar)
	} else {
		fmt.Printf("     %s: downloading...\n", name)
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
		return fmt.Errorf("downloading %s: expected %d bytes, got %d (truncated)", name, resp.ContentLength, written)
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

