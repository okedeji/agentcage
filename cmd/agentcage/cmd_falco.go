package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/okedeji/agentcage/internal/config"
	"github.com/okedeji/agentcage/internal/enforcement"
)

func cmdFalco(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: agentcage falco <subcommand>")
		fmt.Fprintln(os.Stderr, "\nSubcommands:")
		fmt.Fprintln(os.Stderr, "  export-rules    Print generated Falco rules as YAML (for external Falco deployments)")
		os.Exit(1)
	}

	switch args[0] {
	case "export-rules":
		cmdFalcoExportRules(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown falco subcommand: %s\n", args[0])
		fmt.Fprintln(os.Stderr, "usage: agentcage falco export-rules")
		os.Exit(1)
	}
}

func cmdFalcoExportRules(args []string) {
	fs := flag.NewFlagSet("falco export-rules", flag.ExitOnError)
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
	yaml := enforcement.RenderFalcoYAML(rules)

	if *outFile != "" {
		if err := os.WriteFile(*outFile, []byte(yaml), 0644); err != nil {
			fmt.Fprintf(os.Stderr, "error writing rules: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "Falco rules written to %s\n", *outFile)
		return
	}

	fmt.Print(yaml)
}
