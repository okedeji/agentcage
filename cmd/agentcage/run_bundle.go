package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/okedeji/agentcage/internal/cagefile"
	"github.com/okedeji/agentcage/internal/embedded"
)

func prepareBundle(ctx context.Context, agentPath string) (string, error) {
	fi, err := os.Stat(agentPath)
	if err != nil {
		return "", fmt.Errorf("agent path %s: %w", agentPath, err)
	}
	if fi.IsDir() {
		return "", fmt.Errorf("agent path %s is a directory, not a .cage bundle (run 'agentcage pack %s' first)", agentPath, agentPath)
	}
	if !strings.HasSuffix(agentPath, ".cage") {
		return "", fmt.Errorf("agent file %s does not have a .cage extension (run 'agentcage pack <dir>' to create one)", agentPath)
	}

	if fi.Size() > cagefile.DefaultMaxBundleSize {
		return "", fmt.Errorf("bundle %s is %.1f MB, exceeds max bundle size %.1f MB",
			agentPath, float64(fi.Size())/(1024*1024), float64(cagefile.DefaultMaxBundleSize)/(1024*1024))
	}

	if ctx.Err() != nil {
		return "", ctx.Err()
	}

	fmt.Println("Storing bundle...")
	storeDir := filepath.Join(embedded.DataDir(), "bundles")
	store, storeInitErr := cagefile.NewBundleStore(storeDir)
	if storeInitErr != nil {
		return "", storeInitErr
	}

	ref, storeErr := store.Store(agentPath)
	if storeErr != nil {
		return "", fmt.Errorf("storing bundle: %w", storeErr)
	}

	fmt.Println("Verifying bundle...")
	tmpDir, tmpErr := os.MkdirTemp("", "agentcage-verify-*")
	if tmpErr != nil {
		return "", fmt.Errorf("creating temp dir for verify: %w", tmpErr)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	storedPath := store.Path(ref)
	manifest, unpackErr := cagefile.UnpackFile(storedPath, tmpDir)
	if unpackErr != nil {
		_ = os.Remove(storedPath)
		return "", fmt.Errorf("verifying bundle %s: %w", agentPath, unpackErr)
	}
	if err := cagefile.CheckCompatibility(manifest, version); err != nil {
		_ = os.Remove(storedPath)
		return "", err
	}
	if err := cagefile.CheckContentPolicy(manifest); err != nil {
		_ = os.Remove(storedPath)
		return "", fmt.Errorf("bundle content policy: %w", err)
	}

	return ref, nil
}
