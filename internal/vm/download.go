package vm

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
)

// EnsureAssets downloads the kernel, rootfs, and linux agentcage binary if not already cached.
func EnsureAssets(ctx context.Context, agentcageVersion string) error {
	if err := os.MkdirAll(Dir(), 0755); err != nil {
		return fmt.Errorf("creating VM directory: %w", err)
	}

	if err := ensureKernel(ctx); err != nil {
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

func ensureKernel(ctx context.Context) error {
	dest := KernelPath()
	if _, err := os.Stat(dest); err == nil {
		return nil
	}

	arch := runtime.GOARCH
	url := fmt.Sprintf(
		"https://github.com/okedeji/agentcage/releases/download/vm-assets/vmlinux-%s-%s",
		kernelVersion, arch,
	)
	return download(ctx, url, dest)
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
	return download(ctx, url, dest)
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
	if err := download(ctx, url, dest); err != nil {
		return err
	}
	return os.Chmod(dest, 0755)
}

func download(ctx context.Context, url, dest string) error {
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

	f, err := os.OpenFile(dest, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("creating %s: %w", dest, err)
	}
	defer func() { _ = f.Close() }()

	if _, err := io.Copy(f, resp.Body); err != nil {
		return fmt.Errorf("writing %s: %w", dest, err)
	}
	return nil
}
