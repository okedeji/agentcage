package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/okedeji/agentcage/internal/config"
	"github.com/okedeji/agentcage/internal/embedded"
	"github.com/okedeji/agentcage/internal/enforcement"
)

func cmdFalco(args []string) {
	if len(args) < 1 {
		printFalcoUsage()
		os.Exit(1)
	}

	switch args[0] {
	case "export":
		cmdFalcoExport(args[1:])
	case "import":
		cmdFalcoImport(args[1:])
	case "list":
		cmdFalcoList(args[1:])
	case "rm", "remove":
		cmdFalcoRemove(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown falco subcommand: %s\n\n", args[0])
		printFalcoUsage()
		os.Exit(1)
	}
}

func cmdFalcoExport(args []string) {
	fs := flag.NewFlagSet("falco export", flag.ExitOnError)
	configFile := fs.String("config", "", "path to config YAML override file")
	outFile := fs.String("output", "", "write to file instead of stdout")
	_ = fs.Parse(args)

	cfg := config.Defaults()
	if resolved := config.Resolve(*configFile); resolved != "" {
		override, err := config.Load(resolved)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error loading config: %v\n", err)
			os.Exit(1)
		}
		cfg = config.Merge(cfg, override)
	}

	rules, _ := enforcement.GenerateFalcoRules(cfg.Monitoring)
	output := enforcement.RenderFalcoYAML(rules)

	customDir := falcoCustomDir()
	customYAML, err := loadCustomFalcoRules(customDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: loading custom rules: %v\n", err)
	}
	if customYAML != "" {
		output += "\n# Custom imported rules\n" + customYAML
	}

	if *outFile != "" {
		if err := os.WriteFile(*outFile, []byte(output), 0644); err != nil {
			fmt.Fprintf(os.Stderr, "error writing rules: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "Falco rules written to %s\n", *outFile)
		return
	}

	fmt.Print(output)
}

func cmdFalcoImport(args []string) {
	fs := flag.NewFlagSet("falco import", flag.ExitOnError)
	_ = fs.Parse(args)

	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "usage: agentcage falco import <file.yaml> [file2.yaml ...]")
		os.Exit(1)
	}

	dir := falcoCustomDir()
	if err := os.MkdirAll(dir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "error creating custom rules directory: %v\n", err)
		os.Exit(1)
	}

	for _, src := range fs.Args() {
		data, err := os.ReadFile(src)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error reading %s: %v\n", src, err)
			os.Exit(1)
		}

		if err := validateFalcoYAML(data); err != nil {
			fmt.Fprintf(os.Stderr, "FAIL  %s: %v\n", src, err)
			os.Exit(1)
		}

		baseName := filepath.Base(src)
		if !strings.HasPrefix(baseName, "custom_") {
			baseName = "custom_" + baseName
		}
		dest := filepath.Join(dir, baseName)
		if err := os.WriteFile(dest, data, 0644); err != nil {
			fmt.Fprintf(os.Stderr, "error writing %s: %v\n", dest, err)
			os.Exit(1)
		}
		fmt.Printf("  imported: %s\n", dest)
	}
}

func cmdFalcoList(_ []string) {
	cfg := config.Defaults()
	if resolved := config.Resolve(""); resolved != "" {
		override, err := config.Load(resolved)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error loading config: %v\n", err)
			os.Exit(1)
		}
		cfg = config.Merge(cfg, override)
	}

	rules, _ := enforcement.GenerateFalcoRules(cfg.Monitoring)

	fmt.Println("Predefined rules:")
	count := 0
	for cageType, ruleSet := range rules {
		for _, r := range ruleSet {
			fmt.Printf("  %-50s  %-8s  [%s]\n", r.Rule, r.Priority, cageType)
			count++
		}
	}
	if count == 0 {
		fmt.Println("  (none)")
	}

	customDir := falcoCustomDir()
	entries, err := os.ReadDir(customDir)
	customCount := 0
	if err == nil {
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasPrefix(entry.Name(), "custom_") {
				continue
			}
			ext := filepath.Ext(entry.Name())
			if ext != ".yaml" && ext != ".yml" {
				continue
			}
			if customCount == 0 {
				fmt.Println("\nCustom rules:")
			}
			fmt.Printf("  %s\n", entry.Name())
			customCount++
		}
	}
	if customCount == 0 {
		fmt.Println("\nCustom rules: (none)")
	}
}

func cmdFalcoRemove(args []string) {
	fs := flag.NewFlagSet("falco rm", flag.ExitOnError)
	_ = fs.Parse(args)

	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "usage: agentcage falco rm <name> [name2 ...]")
		os.Exit(1)
	}

	dir := falcoCustomDir()
	absDir, err := filepath.Abs(dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error resolving custom rules dir: %v\n", err)
		os.Exit(1)
	}

	hasError := false
	for _, name := range fs.Args() {
		base := filepath.Base(name)
		if !strings.HasPrefix(base, "custom_") {
			base = "custom_" + base
		}
		if !strings.HasSuffix(base, ".yaml") && !strings.HasSuffix(base, ".yml") {
			base += ".yaml"
		}

		path := filepath.Join(absDir, base)
		resolved, err := filepath.Abs(path)
		if err != nil || filepath.Dir(resolved) != absDir {
			fmt.Fprintf(os.Stderr, "FAIL  %s: invalid rule name\n", name)
			hasError = true
			continue
		}

		if _, err := os.Stat(resolved); os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "FAIL  %s: not found\n", name)
			hasError = true
			continue
		}
		if err := os.Remove(resolved); err != nil {
			fmt.Fprintf(os.Stderr, "FAIL  %s: %v\n", name, err)
			hasError = true
			continue
		}
		fmt.Printf("  removed: %s\n", resolved)
	}
	if hasError {
		os.Exit(1)
	}
}

// validateFalcoYAML runs Falco in dry-run mode to validate rule syntax.
// Falls back to basic field checks if the Falco binary isn't available
// (e.g. running from a Mac where only the linux binary exists).
func validateFalcoYAML(data []byte) error {
	falcoBin := filepath.Join(embedded.BinDir(), "falco")
	if _, err := os.Stat(falcoBin); err != nil {
		return validateFalcoYAMLBasic(data)
	}

	tmpFile, err := os.CreateTemp("", "falco-validate-*.yaml")
	if err != nil {
		return validateFalcoYAMLBasic(data)
	}
	defer func() { _ = os.Remove(tmpFile.Name()) }()

	if _, err := tmpFile.Write(data); err != nil {
		_ = tmpFile.Close()
		return validateFalcoYAMLBasic(data)
	}
	_ = tmpFile.Close()

	confFile, err := os.CreateTemp("", "falco-conf-*.yaml")
	if err != nil {
		return validateFalcoYAMLBasic(data)
	}
	defer func() { _ = os.Remove(confFile.Name()) }()
	_, _ = confFile.WriteString("# validation\n")
	_ = confFile.Close()

	out, err := exec.Command(falcoBin, "-c", confFile.Name(), "-r", tmpFile.Name(), "--dry-run").CombinedOutput()
	if err != nil {
		lines := strings.TrimSpace(string(out))
		if lines == "" {
			return fmt.Errorf("falco validation failed: %w", err)
		}
		return fmt.Errorf("falco validation failed:\n%s", lines)
	}
	return nil
}

func validateFalcoYAMLBasic(data []byte) error {
	content := string(data)
	if !strings.Contains(content, "rule:") {
		return fmt.Errorf("missing 'rule:' field")
	}
	if !strings.Contains(content, "condition:") {
		return fmt.Errorf("missing 'condition:' field")
	}
	if !strings.Contains(content, "output:") {
		return fmt.Errorf("missing 'output:' field")
	}
	if !strings.Contains(content, "priority:") {
		return fmt.Errorf("missing 'priority:' field")
	}
	return nil
}

func loadCustomFalcoRules(dir string) (string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}

	var b strings.Builder
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), "custom_") {
			continue
		}
		ext := filepath.Ext(entry.Name())
		if ext != ".yaml" && ext != ".yml" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			return "", fmt.Errorf("reading %s: %w", entry.Name(), err)
		}
		b.Write(data)
		b.WriteString("\n")
	}
	return b.String(), nil
}

func falcoRulesDir() string {
	return filepath.Join(embedded.RunDir(), "falco", "rules.d")
}

func falcoCustomDir() string {
	return falcoRulesDir()
}

func printFalcoUsage() {
	fmt.Fprintf(os.Stderr, `Usage: agentcage falco <subcommand>

Manage Falco runtime monitoring rules.

Subcommands:
  export    Export predefined + custom rules as Falco YAML
  import          Import custom Falco rule files
  list            List predefined and custom rules
  rm              Remove a custom rule

Examples:
  agentcage falco list
  agentcage falco import custom-secret-read.yaml
  agentcage falco export
  agentcage falco export --output rules.yaml
  agentcage falco rm custom-secret-read
`)
}
