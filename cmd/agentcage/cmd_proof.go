package main

import (
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/okedeji/agentcage/internal/assessment"
	"github.com/okedeji/agentcage/internal/embedded"
	"github.com/okedeji/agentcage/proofs"
)

func cmdProof(args []string) {
	if len(args) < 1 {
		printProofUsage()
		os.Exit(1)
	}

	switch args[0] {
	case "add":
		cmdProofAdd(args[1:])
	case "list":
		cmdProofList(args[1:])
	case "validate":
		cmdProofValidate(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown proof subcommand: %s\n\n", args[0])
		printProofUsage()
		os.Exit(1)
	}
}

func cmdProofAdd(args []string) {
	f := flag.NewFlagSet("proof add", flag.ExitOnError)
	_ = f.Parse(args)

	if f.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "usage: agentcage proof add <file.yaml> [file2.yaml ...]")
		os.Exit(1)
	}

	dir := proofsDir()

	for _, src := range f.Args() {
		data, err := os.ReadFile(src)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error reading %s: %v\n", src, err)
			os.Exit(1)
		}

		if err := validateProofBytes(data, src); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}

		dest := filepath.Join(dir, filepath.Base(src))
		if err := os.WriteFile(dest, data, 0644); err != nil {
			fmt.Fprintf(os.Stderr, "error writing %s: %v\n", dest, err)
			os.Exit(1)
		}
		fmt.Printf("  added: %s\n", dest)
	}
}

func cmdProofList(args []string) {
	_ = args
	dir := proofsDir()

	lib, err := assessment.LoadPlaybooks(dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error loading proofs from %s: %v\n", dir, err)
		os.Exit(1)
	}

	pbs := lib.List()
	if len(pbs) == 0 {
		fmt.Println("No proofs found.")
		return
	}

	fmt.Printf("Proofs (%s):\n\n", dir)
	for _, pb := range pbs {
		safety := "safe"
		if pb.Safety.Destructive {
			safety = "DESTRUCTIVE"
		}
		fmt.Printf("  %-30s %-20s %s\n", pb.VulnClass, pb.ValidationType, safety)
	}
}

func cmdProofValidate(args []string) {
	f := flag.NewFlagSet("proof validate", flag.ExitOnError)
	_ = f.Parse(args)

	if f.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "usage: agentcage proof validate <file.yaml> [file2.yaml ...]")
		os.Exit(1)
	}

	hasError := false
	for _, path := range f.Args() {
		data, err := os.ReadFile(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "FAIL  %s: %v\n", path, err)
			hasError = true
			continue
		}
		if err := validateProofBytes(data, path); err != nil {
			fmt.Fprintf(os.Stderr, "FAIL  %s: %v\n", path, err)
			hasError = true
			continue
		}
		fmt.Printf("OK    %s\n", path)
	}
	if hasError {
		os.Exit(1)
	}
}

func validateProofBytes(data []byte, name string) error {
	tmpDir, err := os.MkdirTemp("", "proof-validate-*")
	if err != nil {
		return fmt.Errorf("creating temp dir: %w", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	tmpFile := filepath.Join(tmpDir, filepath.Base(name))
	if err := os.WriteFile(tmpFile, data, 0644); err != nil {
		return fmt.Errorf("writing temp file: %w", err)
	}

	_, err = assessment.LoadPlaybooks(tmpDir)
	return err
}

func proofsDir() string {
	return filepath.Join(embedded.DataDir(), "proofs")
}

// seedDefaultProofs copies the embedded default proof definitions into the
// proofs directory if it doesn't exist yet.
func seedDefaultProofs(dir string) error {
	if _, err := os.Stat(dir); err == nil {
		return nil
	}

	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("creating proofs directory %s: %w", dir, err)
	}

	entries, err := fs.ReadDir(proofs.Defaults, ".")
	if err != nil {
		return fmt.Errorf("reading embedded proofs: %w", err)
	}

	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		data, err := proofs.Defaults.ReadFile(e.Name())
		if err != nil {
			return fmt.Errorf("reading embedded proof %s: %w", e.Name(), err)
		}
		dest := filepath.Join(dir, e.Name())
		if err := os.WriteFile(dest, data, 0644); err != nil {
			return fmt.Errorf("writing proof %s: %w", dest, err)
		}
	}

	return nil
}

func printProofUsage() {
	fmt.Println(`Usage: agentcage proof <subcommand>

Manage validation rules that define how validator cages confirm vulnerability findings.

Subcommands:
  add <file.yaml>        Add a validation rule (validates before copying)
  list                   List all validation rules
  validate <file.yaml>   Check a validation rule file is valid without adding it`)
}
