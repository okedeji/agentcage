package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/okedeji/agentcage/internal/cagefile"
)

func cmdPack(args []string) {
	fs := flag.NewFlagSet("pack", flag.ExitOnError)
	output := fs.String("output", "", "output .cage file path (default: <dir-name>.cage)")
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

	manifest, err := cagefile.PackToFile(dir, version, outPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	outInfo, _ := os.Stat(outPath)
	sizeMB := float64(outInfo.Size()) / (1024 * 1024)

	fmt.Printf("\n  Bundle:     %s (%.1f MB)\n", outPath, sizeMB)
	fmt.Printf("  Runtime:    %s\n", manifest.Runtime)
	fmt.Printf("  Entrypoint: %s\n", manifest.Entrypoint)
	if len(manifest.SystemDeps) > 0 {
		fmt.Printf("  Deps:       %s\n", strings.Join(manifest.SystemDeps, ", "))
	}
	fmt.Printf("  Hash:       %s\n", manifest.FilesHash)
	fmt.Println("\nReady. Use 'agentcage run --agent", outPath, "--target <host>' to start an assessment.")
}
