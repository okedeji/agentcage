package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/okedeji/agentcage/internal/config"
)

func cmdConfig(args []string) {
	if len(args) < 1 {
		printConfigUsage()
		os.Exit(1)
	}

	switch args[0] {
	case "show":
		cmdConfigShow(args[1:])
	case "export":
		cmdConfigExport(args[1:])
	case "import":
		cmdConfigImport(args[1:])
	case "get":
		cmdConfigGet(args[1:])
	case "path":
		cmdConfigPath(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown config subcommand: %s\n\n", args[0])
		printConfigUsage()
		os.Exit(1)
	}
}

func cmdConfigShow(_ []string) {
	path := config.Resolve("")
	if path == "" {
		fmt.Println("No config file found. Using built-in defaults.")
		fmt.Println("Run 'agentcage init' to generate one, or 'agentcage config import <file>' to install one.")
		return
	}

	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading config: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("# %s\n", path)
	fmt.Print(string(data))
}

func cmdConfigExport(args []string) {
	fs := flag.NewFlagSet("config export", flag.ExitOnError)
	outFile := fs.String("output", "", "write to file instead of stdout")
	_ = fs.Parse(args)

	cfg := config.Defaults()
	if resolved := config.Resolve(""); resolved != "" {
		override, err := config.Load(resolved)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error loading config: %v\n", err)
			os.Exit(1)
		}
		cfg = config.Merge(cfg, override)
	}

	yaml, err := config.Marshal(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error marshaling config: %v\n", err)
		os.Exit(1)
	}

	if *outFile != "" {
		if err := os.WriteFile(*outFile, yaml, 0600); err != nil {
			fmt.Fprintf(os.Stderr, "error writing config to %s: %v\n", *outFile, err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "Config exported to %s\n", *outFile)
		return
	}

	fmt.Print(string(yaml))
}

func cmdConfigImport(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: agentcage config import <file>")
		os.Exit(1)
	}

	src := args[0]
	data, err := os.ReadFile(src)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading %s: %v\n", src, err)
		os.Exit(1)
	}

	// Validate before writing.
	if _, err := config.Parse(data); err != nil {
		fmt.Fprintf(os.Stderr, "invalid config: %v\n", err)
		os.Exit(1)
	}

	dest := config.DefaultPath()
	if err := os.MkdirAll(filepath.Dir(dest), 0755); err != nil {
		fmt.Fprintf(os.Stderr, "error creating config directory: %v\n", err)
		os.Exit(1)
	}
	if err := os.WriteFile(dest, data, 0600); err != nil {
		fmt.Fprintf(os.Stderr, "error writing config: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Config imported to %s\n", dest)
}

func cmdConfigGet(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: agentcage config get <key> (e.g. assessment.token_budget)")
		os.Exit(1)
	}

	key := args[0]
	cfg := config.Defaults()
	if resolved := config.Resolve(""); resolved != "" {
		override, err := config.Load(resolved)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error loading config: %v\n", err)
			os.Exit(1)
		}
		cfg = config.Merge(cfg, override)
	}

	server := config.NewServer(cfg)
	val, err := server.GetValue(context.Background(), key)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(val)
}

func cmdConfigPath(_ []string) {
	path := config.Resolve("")
	if path == "" {
		fmt.Println("(none — using built-in defaults)")
		return
	}
	fmt.Println(path)
}

func printConfigUsage() {
	fmt.Fprintf(os.Stderr, `usage: agentcage config <subcommand>

Subcommands:
  show              Print current config (from file, or note that defaults are used)
  export            Dump resolved config as YAML (--output <file> to write to file)
  import <file>     Install a config file to ~/.agentcage/config.yaml
  get <key>         Get a single config value (e.g. assessment.token_budget)
  path              Print which config file is being used

Examples:
  agentcage config show
  agentcage config export --output /tmp/agentcage-config.yaml
  agentcage config import agentcage-config.yaml
  agentcage config get assessment.token_budget
`)
}
