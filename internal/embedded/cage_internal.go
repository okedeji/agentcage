package embedded

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/go-logr/logr"
)

// CageInternalDownloader downloads the cage-internal binaries (cage-init,
// findings-sidecar, directive-sidecar, payload-proxy) from GitHub releases.
// These run inside cages (real or subprocess) and are not long-running daemons.
type CageInternalDownloader struct {
	log     logr.Logger
	version string
}

func NewCageInternalDownloader(log logr.Logger, version string) *CageInternalDownloader {
	return &CageInternalDownloader{log: log.WithValues("service", "cage-internal"), version: version}
}

func (c *CageInternalDownloader) Name() string    { return "cage-internal" }
func (c *CageInternalDownloader) IsExternal() bool { return false }

func (c *CageInternalDownloader) binDir() string {
	return filepath.Join(BinDir(), "cage-internal")
}

func (c *CageInternalDownloader) Download(ctx context.Context) error {
	dir := c.binDir()
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("creating cage-internal dir: %w", err)
	}

	arch := runtime.GOARCH
	binaries := []string{"cage-init", "findings-sidecar", "directive-sidecar", "payload-proxy"}

	for _, name := range binaries {
		dest := filepath.Join(dir, name)
		if _, err := os.Stat(dest); err == nil {
			continue
		}

		url := fmt.Sprintf(
			"https://github.com/okedeji/agentcage/releases/download/v%s/cage-internal-%s-linux-%s",
			c.version, name, arch,
		)
		c.log.Info("downloading", "binary", name, "url", url)
		if err := downloadBinary(ctx, url, dest); err != nil {
			return fmt.Errorf("downloading %s: %w", name, err)
		}
	}
	return nil
}

func (c *CageInternalDownloader) Start(_ context.Context) error { return nil }
func (c *CageInternalDownloader) Stop(_ context.Context) error  { return nil }

func (c *CageInternalDownloader) Health(_ context.Context) error {
	dir := c.binDir()
	for _, name := range []string{"cage-init", "findings-sidecar"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			return fmt.Errorf("%s not found: %w", name, err)
		}
	}
	return nil
}
