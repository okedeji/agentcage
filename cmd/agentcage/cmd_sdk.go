package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/okedeji/agentcage/internal/config"
	"github.com/okedeji/agentcage/internal/ui"
)

func cmdSDK(args []string) {
	if len(args) < 1 {
		printSDKUsage()
		os.Exit(1)
	}
	switch args[0] {
	case "install":
		cmdSDKInstall(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown sdk command: %s\n", args[0])
		printSDKUsage()
		os.Exit(1)
	}
}

func printSDKUsage() {
	fmt.Print(`Usage: agentcage sdk <command>

Commands:
  install [--runtime node]   Install the agent SDK for local development

Examples:
  agentcage sdk install                # install TypeScript SDK in current directory
  agentcage sdk install --runtime go   # (future) install Go SDK
`)
}

func cmdSDKInstall(args []string) {
	fs := flag.NewFlagSet("sdk install", flag.ExitOnError)
	runtime := fs.String("runtime", "node", "SDK runtime: node (default), python, go")
	_ = fs.Parse(args)

	switch *runtime {
	case "node":
		installNodeSDK()
	case "python", "go":
		ui.Fail("SDK for %s is not yet available", *runtime)
		os.Exit(1)
	default:
		ui.Fail("unknown runtime: %s", *runtime)
		os.Exit(1)
	}
}

func installNodeSDK() {
	ui.Section("SDK Install")

	// Find the SDK tarball: check local cache first, then download.
	sdkPath := findSDKTarball()
	if sdkPath == "" {
		ui.Step("Downloading SDK...")
		var err error
		sdkPath, err = downloadSDKTarball()
		if err != nil {
			ui.Fail("downloading SDK: %v", err)
			os.Exit(1)
		}
		ui.OK("SDK downloaded")
	} else {
		ui.Step("Using cached SDK: %s", filepath.Base(sdkPath))
	}

	// Run npm install with the tarball.
	ui.Step("Running npm install...")
	cmd := exec.Command("npm", "install", sdkPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		ui.Fail("npm install failed: %v", err)
		os.Exit(1)
	}

	ui.OK("@agentcage/sdk installed")
	ui.Step("Import: import { AgentSDK } from '@agentcage/sdk'")
}

// findSDKTarball checks the local agentcage home for a cached SDK tarball.
func findSDKTarball() string {
	home := config.HomeDir()
	pattern := filepath.Join(home, "sdk", "agentcage-sdk-*.tgz")
	matches, _ := filepath.Glob(pattern)
	if len(matches) > 0 {
		return matches[len(matches)-1]
	}
	// Also check bin directory (downloaded by CageInternalDownloader).
	pattern = filepath.Join(home, "bin", "agentcage-sdk-*.tgz")
	matches, _ = filepath.Glob(pattern)
	if len(matches) > 0 {
		return matches[len(matches)-1]
	}
	return ""
}

// downloadSDKTarball fetches the SDK from the GitHub release.
func downloadSDKTarball() (string, error) {
	sdkDir := filepath.Join(config.HomeDir(), "sdk")
	if err := os.MkdirAll(sdkDir, 0755); err != nil {
		return "", err
	}

	url := fmt.Sprintf(
		"https://github.com/okedeji/agentcage/releases/download/v%s/agentcage-sdk-%s.tgz",
		version, version,
	)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download returned HTTP %d", resp.StatusCode)
	}

	dest := filepath.Join(sdkDir, fmt.Sprintf("agentcage-sdk-%s.tgz", version))
	f, err := os.OpenFile(dest, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return "", err
	}
	if _, err := io.Copy(f, resp.Body); err != nil {
		_ = f.Close()
		_ = os.Remove(dest)
		return "", err
	}
	_ = f.Close()
	return dest, nil
}
