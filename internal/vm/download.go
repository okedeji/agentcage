package vm

import (
	"compress/gzip"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/schollz/progressbar/v3"
)

// knownChecksums maps asset filenames to expected SHA-256 hex
// digests. Populate at release time. When empty, verification is
// skipped with a warning; only acceptable during development.
var knownChecksums = map[string]string{
	// "vmlinux-6.12-arm64":         "sha256-hex-here",
	// "vmlinux-6.12-amd64":         "sha256-hex-here",
	// "rootfs-arm64.img":           "sha256-hex-here",
	// "rootfs-amd64.img":           "sha256-hex-here",
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
	for _, p := range []string{KernelPath(), RootfsPath(), LinuxBinaryPath(), CageRootfsPath()} {
		if _, err := os.Stat(p); err != nil {
			needed++
		}
	}
	if needed == 0 {
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
	if err := ensureCageRootfs(ctx, agentcageVersion); err != nil {
		return fmt.Errorf("ensuring cage rootfs: %w", err)
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

func ensureCageRootfs(ctx context.Context, version string) error {
	dest := CageRootfsPath()
	if _, err := os.Stat(dest); err == nil {
		return nil
	}

	arch := runtime.GOARCH
	url := fmt.Sprintf(
		"https://github.com/okedeji/agentcage/releases/download/v%s/cage-rootfs-%s.ext4.gz",
		version, arch,
	)
	compressed := dest + ".gz"
	if err := download(ctx, url, compressed, filepath.Base(dest)); err != nil {
		return err
	}
	if err := decompressGzipFile(compressed, dest); err != nil {
		_ = os.Remove(compressed)
		return fmt.Errorf("decompressing cage rootfs: %w", err)
	}
	_ = os.Remove(compressed)
	return nil
}

func decompressGzipFile(src, dest string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()

	gr, err := gzip.NewReader(in)
	if err != nil {
		return err
	}
	defer func() { _ = gr.Close() }()

	out, err := os.OpenFile(dest, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}

	if _, err := io.Copy(out, gr); err != nil {
		_ = out.Close()
		_ = os.Remove(dest)
		return err
	}
	return out.Close()
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

// download fetches url to dest using curl for reliability (retries,
// resume, TLS handling) and renders progress with our own UI.
func download(ctx context.Context, url, dest, displayName string) error {
	if err := os.MkdirAll(filepath.Dir(dest), 0755); err != nil {
		return fmt.Errorf("creating directory for %s: %w", dest, err)
	}

	name := displayName
	if name == "" {
		name = filepath.Base(dest)
	}

	tmp := dest + ".tmp"

	// Get total file size so we can render a progress bar. GitHub
	// release URLs redirect to a CDN, so -L follows the chain and
	// we parse Content-Length from the final response headers.
	headCmd := exec.CommandContext(ctx, "curl",
		"-sSLI",
		"--connect-timeout", "30",
		url,
	)
	headOut, _ := headCmd.Output()

	var totalBytes int64
	for _, line := range strings.Split(string(headOut), "\n") {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(line)), "content-length:") {
			val := strings.TrimSpace(strings.SplitN(line, ":", 2)[1])
			totalBytes, _ = strconv.ParseInt(val, 10, 64)
		}
	}

	// Download with curl writing to a temp file that we poll for size.
	cmd := exec.CommandContext(ctx, "curl",
		"-fSL",
		"--retry", "3",
		"--retry-delay", "2",
		"--connect-timeout", "30",
		"-C", "-",
		"-o", tmp,
		url,
	)
	cmd.Stderr = io.Discard

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("starting download of %s: %w", name, err)
	}

	// Poll file size and render progress.
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	var bar *progressbar.ProgressBar
	if totalBytes > 0 {
		bar = progressbar.DefaultBytes(totalBytes, "     "+name)
	} else {
		fmt.Printf("     %s: downloading...\n", name)
	}

	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case err := <-done:
			// Final size update.
			if bar != nil {
				if info, statErr := os.Stat(tmp); statErr == nil {
					_ = bar.Set64(info.Size())
				}
				_ = bar.Finish()
			}
			if err != nil {
				_ = os.Remove(tmp)
				return fmt.Errorf("downloading %s: %w", name, err)
			}
			if err := os.Rename(tmp, dest); err != nil {
				_ = os.Remove(tmp)
				return fmt.Errorf("finalizing %s: %w", dest, err)
			}
			return nil

		case <-ticker.C:
			if bar != nil {
				if info, err := os.Stat(tmp); err == nil {
					_ = bar.Set64(info.Size())
				}
			}
		}
	}
}

