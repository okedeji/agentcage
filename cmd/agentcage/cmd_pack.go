package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/okedeji/agentcage/internal/cagefile"
	"github.com/okedeji/agentcage/internal/config"
)

func cmdPack(args []string) {
	fs := flag.NewFlagSet("pack", flag.ExitOnError)
	output := fs.String("output", "", "output .cage file path (default: <dir-name>.cage)")
	maxSizeMB := fs.Int64("max-size", 0, "max directory size in MB (default: 2048)")
	_ = fs.Parse(args)

	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "usage: agentcage pack <directory> [--output path.cage]")
		os.Exit(1)
	}

	dir := fs.Arg(0)
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		fmt.Fprintf(os.Stderr, "error: %s is not a directory\n", dir)
		os.Exit(1)
	}

	outPath := *output
	if outPath == "" {
		name := filepath.Base(dir)
		name = strings.TrimSuffix(name, "/")
		outPath = name + ".cage"
	}

	fmt.Printf("Packing %s...\n", dir)
	fmt.Println("  Scanning files and computing hashes...")

	var maxSize int64
	if *maxSizeMB > 0 {
		maxSize = *maxSizeMB * 1024 * 1024
	}

	keyPath := filepath.Join(config.HomeDir(), "signing-key.pem")
	signingKey, keyErr := cagefile.LoadOrGenerateSigningKey(keyPath)
	if keyErr != nil {
		fmt.Fprintf(os.Stderr, "warning: signing disabled: %v\n", keyErr)
	}
	var packOpts *cagefile.PackOptions
	if signingKey != nil {
		packOpts = &cagefile.PackOptions{SigningKey: signingKey}
	}

	manifest, err := cagefile.PackToFile(dir, version, outPath, maxSize, packOpts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	var sizeMB float64
	if outInfo, statErr := os.Stat(outPath); statErr == nil {
		sizeMB = float64(outInfo.Size()) / (1024 * 1024)
	}

	fmt.Printf("\n  Bundle:     %s (%.1f MB)\n", outPath, sizeMB)
	fmt.Printf("  Version:    %s\n", manifest.Version)
	fmt.Printf("  Runtime:    %s\n", manifest.Runtime)
	fmt.Printf("  Entrypoint: %s\n", manifest.Entrypoint)
	if len(manifest.SystemDeps) > 0 {
		fmt.Printf("  Deps:       %s\n", strings.Join(manifest.SystemDeps, ", "))
	}
	if len(manifest.Packages) > 0 {
		fmt.Printf("  Packages:   %s\n", strings.Join(manifest.Packages, ", "))
	}
	if len(manifest.PipDeps) > 0 {
		fmt.Printf("  Pip:        %s\n", strings.Join(manifest.PipDeps, ", "))
	}
	if len(manifest.NpmDeps) > 0 {
		fmt.Printf("  Npm:        %s\n", strings.Join(manifest.NpmDeps, ", "))
	}
	if len(manifest.GoDeps) > 0 {
		fmt.Printf("  Go:         %s\n", strings.Join(manifest.GoDeps, ", "))
	}
	fmt.Printf("  Hash:       %s\n", manifest.FilesHash)
	fmt.Printf("\nReady. Use 'agentcage run --agent %s --target <host>' to start an assessment.\n", outPath)
}
