package embedded

import (
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"

	"github.com/go-logr/logr"
)

const (
	firecrackerVersion = "1.14.1"

	// CI kernel: pre-built by the Firecracker team, tested against
	// each Firecracker release. Hosted on S3 at
	// spec.ccfc.min/firecracker-ci/v{major.minor}/{arch}/vmlinux-{version}.
	ciKernelVersion = "6.1.155"
	ciKernelFCMinor = "1.14"
)

// FirecrackerDownloader downloads the Firecracker VMM binary and a
// Linux kernel. Unlike other embedded services, Firecracker is not a
// long-running subprocess; it's started per-cage by the VM
// provisioner.
type FirecrackerDownloader struct {
	log     logr.Logger
	version string
}

func NewFirecrackerDownloader(log logr.Logger, version string) *FirecrackerDownloader {
	return &FirecrackerDownloader{log: log.WithValues("service", "firecracker"), version: version}
}

func (f *FirecrackerDownloader) Name() string      { return "firecracker" }
func (f *FirecrackerDownloader) IsExternal() bool   { return false }

func (f *FirecrackerDownloader) BinPath() string {
	return filepath.Join(BinDir(), "firecracker")
}

func (f *FirecrackerDownloader) KernelPath() string {
	return filepath.Join(BinDir(), "vmlinux")
}

func (f *FirecrackerDownloader) Download(ctx context.Context) error {
	if err := f.downloadFirecracker(ctx); err != nil {
		return err
	}
	if err := f.downloadKernel(ctx); err != nil {
		return err
	}
	return f.downloadCageRootfs(ctx)
}

func (f *FirecrackerDownloader) downloadFirecracker(ctx context.Context) error {
	dest := f.BinPath()
	if _, err := os.Stat(dest); err == nil {
		return nil
	}

	arch := archSuffix()
	url := fmt.Sprintf("https://github.com/firecracker-microvm/firecracker/releases/download/v%s/firecracker-v%s-%s.tgz",
		firecrackerVersion, firecrackerVersion, arch)

	f.log.Info("downloading firecracker", "version", firecrackerVersion, "url", url)

	archivePath := filepath.Join(BinDir(), "firecracker-"+firecrackerVersion+".tgz")
	if err := downloadBinary(ctx, url, archivePath); err != nil {
		return fmt.Errorf("downloading firecracker: %w", err)
	}

	archive, err := os.Open(archivePath)
	if err != nil {
		return fmt.Errorf("opening firecracker archive: %w", err)
	}
	defer func() { _ = archive.Close() }()

	extractDir := filepath.Join(BinDir(), "firecracker-extract")
	if err := extractTarGz(archive, extractDir); err != nil {
		_ = os.Remove(archivePath)
		return fmt.Errorf("extracting firecracker: %w", err)
	}
	_ = os.Remove(archivePath)

	src := filepath.Join(extractDir, fmt.Sprintf("release-v%s-%s", firecrackerVersion, arch), "firecracker-v"+firecrackerVersion+"-"+arch)
	if err := os.Rename(src, dest); err != nil {
		_ = os.RemoveAll(extractDir)
		return fmt.Errorf("moving firecracker binary: %w", err)
	}
	_ = os.RemoveAll(extractDir)

	return nil
}

func (f *FirecrackerDownloader) downloadKernel(ctx context.Context) error {
	dest := f.KernelPath()
	if _, err := os.Stat(dest); err == nil {
		return nil
	}

	arch := archSuffix()
	url := fmt.Sprintf("https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/v%s/%s/vmlinux-%s",
		ciKernelFCMinor, arch, ciKernelVersion)

	f.log.Info("downloading cage kernel", "version", ciKernelVersion, "arch", arch, "url", url)
	return downloadBinary(ctx, url, dest)
}

func (f *FirecrackerDownloader) downloadCageRootfs(ctx context.Context) error {
	dest := filepath.Join(VMDir(), "cage-rootfs.img")
	if _, err := os.Stat(dest); err == nil {
		return nil
	}

	arch := runtime.GOARCH
	url := fmt.Sprintf("https://github.com/okedeji/agentcage/releases/download/v%s/cage-rootfs-%s.ext4.gz",
		f.version, arch)

	compressed := dest + ".gz"
	f.log.Info("downloading cage rootfs", "url", url)
	if err := downloadBinaryWithLog(ctx, url, compressed, f.log); err != nil {
		return err
	}

	f.log.Info("decompressing cage rootfs")
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

	tmp := dest + ".tmp"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}

	if _, err := io.Copy(out, gr); err != nil {
		_ = out.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := out.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, dest)
}

// Start is a no-op. Firecracker is started per-cage, not as a daemon.
func (f *FirecrackerDownloader) Start(_ context.Context) error {
	return nil
}

// Stop is a no-op.
func (f *FirecrackerDownloader) Stop(_ context.Context) error {
	return nil
}

// Health checks that the binary exists.
func (f *FirecrackerDownloader) Health(_ context.Context) error {
	if _, err := os.Stat(f.BinPath()); err != nil {
		return fmt.Errorf("firecracker binary not found: %w", err)
	}
	if _, err := os.Stat(f.KernelPath()); err != nil {
		return fmt.Errorf("kernel binary not found: %w", err)
	}
	return nil
}
