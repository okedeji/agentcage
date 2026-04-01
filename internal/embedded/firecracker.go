package embedded

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/go-logr/logr"
)

const (
	firecrackerVersion = "1.6.0"
	kernelVersion      = "6.1"
)

// FirecrackerDownloader downloads the Firecracker VMM binary and a Linux
// kernel. Unlike other embedded services, Firecracker is not a long-running
// subprocess — it's started per-cage by the VM provisioner.
type FirecrackerDownloader struct {
	log logr.Logger
}

func NewFirecrackerDownloader(log logr.Logger) *FirecrackerDownloader {
	return &FirecrackerDownloader{log: log.WithValues("service", "firecracker")}
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
	return f.downloadKernel(ctx)
}

func (f *FirecrackerDownloader) downloadFirecracker(ctx context.Context) error {
	dest := f.BinPath()
	if _, err := os.Stat(dest); err == nil {
		return nil
	}

	arch := archSuffix()
	if runtime.GOOS != "linux" {
		f.log.Info("firecracker only runs on Linux — skipping download (local mode)")
		if err := os.WriteFile(dest, []byte("#!/bin/sh\necho 'firecracker requires linux'"), 0755); err != nil {
			return fmt.Errorf("creating stub: %w", err)
		}
		return nil
	}

	url := fmt.Sprintf("https://github.com/firecracker-microvm/firecracker/releases/download/v%s/firecracker-v%s-%s",
		firecrackerVersion, firecrackerVersion, arch)

	f.log.Info("downloading firecracker", "version", firecrackerVersion, "arch", arch)
	return downloadBinary(ctx, url, dest)
}

func (f *FirecrackerDownloader) downloadKernel(ctx context.Context) error {
	dest := f.KernelPath()
	if _, err := os.Stat(dest); err == nil {
		return nil
	}

	if runtime.GOOS != "linux" {
		f.log.Info("kernel only needed on Linux — skipping download (local mode)")
		if err := os.WriteFile(dest, []byte{}, 0644); err != nil {
			return fmt.Errorf("creating stub kernel: %w", err)
		}
		return nil
	}

	arch := archSuffix()
	url := fmt.Sprintf("https://s3.amazonaws.com/spec.ccfc.min/img/quickstart_guide/%s/kernels/vmlinux-%s.bin",
		arch, kernelVersion)

	f.log.Info("downloading linux kernel", "version", kernelVersion, "arch", arch)
	return downloadBinary(ctx, url, dest)
}

// Start is a no-op — Firecracker is started per-cage, not as a daemon.
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
