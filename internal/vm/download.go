package vm

import (
	"compress/gzip"
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

	"github.com/vbauerster/mpb/v8"
	"github.com/vbauerster/mpb/v8/decor"
	"golang.org/x/sync/errgroup"
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

// EnsureAssets downloads the kernel, rootfs, and linux agentcage binary if not already cached.
func EnsureAssets(ctx context.Context, agentcageVersion string) error {
	if err := os.MkdirAll(Dir(), 0755); err != nil {
		return fmt.Errorf("creating VM directory: %w", err)
	}

	// Check which assets need downloading before creating progress bars.
	needed := 0
	if _, err := os.Stat(KernelPath()); err != nil {
		needed++
	}
	if _, err := os.Stat(RootfsPath()); err != nil {
		needed++
	}
	if _, err := os.Stat(LinuxBinaryPath()); err != nil {
		needed++
	}
	if needed == 0 {
		fmt.Println("     All assets cached")
		return nil
	}

	p := mpb.NewWithContext(ctx, mpb.WithWidth(60))

	g, gCtx := errgroup.WithContext(ctx)
	g.Go(func() error {
		if err := ensureKernel(gCtx, agentcageVersion, p); err != nil {
			return fmt.Errorf("ensuring kernel: %w", err)
		}
		return nil
	})
	g.Go(func() error {
		if err := ensureRootfs(gCtx, agentcageVersion, p); err != nil {
			return fmt.Errorf("ensuring rootfs: %w", err)
		}
		return nil
	})
	g.Go(func() error {
		if err := ensureLinuxBinary(gCtx, agentcageVersion, p); err != nil {
			return fmt.Errorf("ensuring linux binary: %w", err)
		}
		return nil
	})
	err := g.Wait()
	p.Wait()
	return err
}

func ensureKernel(ctx context.Context, _ string, p *mpb.Progress) error {
	dest := KernelPath()
	if _, err := os.Stat(dest); err == nil {
		return nil
	}

	// Ubuntu cloud kernels are built with the virtio drivers that
	// Apple Virtualization.framework needs (virtio-mmio, virtio-blk,
	// virtio-net, virtio-console, virtiofs). Firecracker kernels
	// from AWS S3 lack these and fail to boot under VZ.
	arch := runtime.GOARCH
	var ubuntuArch string
	if arch == "arm64" {
		ubuntuArch = "arm64"
	} else {
		ubuntuArch = "amd64"
	}
	url := fmt.Sprintf(
		"https://cloud-images.ubuntu.com/releases/noble/release/unpacked/ubuntu-24.04-server-cloudimg-%s-vmlinuz-generic",
		ubuntuArch,
	)
	compressed := dest + ".gz"
	if err := download(ctx, url, compressed, p); err != nil {
		return err
	}
	if err := decompressGzip(compressed, dest); err != nil {
		_ = os.Remove(compressed)
		return fmt.Errorf("decompressing kernel: %w", err)
	}
	_ = os.Remove(compressed)
	return verifyChecksum(dest)
}

func ensureRootfs(ctx context.Context, version string, p *mpb.Progress) error {
	dest := RootfsPath()
	if _, err := os.Stat(dest); err == nil {
		return nil
	}

	arch := runtime.GOARCH
	url := fmt.Sprintf(
		"https://github.com/okedeji/agentcage/releases/download/v%s/rootfs-%s.img",
		version, arch,
	)
	if err := download(ctx, url, dest, p); err != nil {
		return err
	}
	return verifyChecksum(dest)
}

func ensureLinuxBinary(ctx context.Context, version string, p *mpb.Progress) error {
	dest := LinuxBinaryPath()
	if _, err := os.Stat(dest); err == nil {
		return nil
	}

	arch := runtime.GOARCH
	url := fmt.Sprintf(
		"https://github.com/okedeji/agentcage/releases/download/v%s/agentcage-linux-%s",
		version, arch,
	)
	if err := download(ctx, url, dest, p); err != nil {
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

func download(ctx context.Context, url, dest string, p *mpb.Progress) error {
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

	name := filepath.Base(dest)
	var reader io.Reader = resp.Body
	if resp.ContentLength > 0 {
		bar := p.AddBar(resp.ContentLength,
			mpb.PrependDecorators(
				decor.Name(name, decor.WCSyncSpaceR),
				decor.CountersKibiByte("% .1f / % .1f"),
			),
			mpb.AppendDecorators(
				decor.EwmaETA(decor.ET_STYLE_GO, 30),
				decor.Name(" "),
				decor.EwmaSpeed(decor.SizeB1024(0), "% .1f", 30),
			),
		)
		reader = bar.ProxyReader(resp.Body)
	} else {
		fmt.Printf("  %s: downloading...\n", name)
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

func decompressGzip(src, dest string) error {
	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("opening %s: %w", src, err)
	}
	defer func() { _ = in.Close() }()

	gr, err := gzip.NewReader(in)
	if err != nil {
		return fmt.Errorf("creating gzip reader: %w", err)
	}
	defer func() { _ = gr.Close() }()

	out, err := os.OpenFile(dest, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("creating %s: %w", dest, err)
	}

	if _, err := io.Copy(out, gr); err != nil {
		_ = out.Close()
		_ = os.Remove(dest)
		return fmt.Errorf("decompressing: %w", err)
	}
	return out.Close()
}
