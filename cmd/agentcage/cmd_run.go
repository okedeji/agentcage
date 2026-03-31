package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
)

func cmdRun(args []string) {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	agent := fs.String("agent", "", "path to .cage bundle or agent directory")
	target := fs.String("target", "", "target host(s), comma-separated")
	tokenBudget := fs.Int64("token-budget", 0, "LLM token budget (default: from config)")
	maxDuration := fs.String("max-duration", "", "assessment time limit (e.g. 30m, 4h)")
	compliance := fs.String("compliance", "", "compliance framework (soc2, hipaa, pci_dss)")
	config := fs.String("config", "", "path to config YAML override file")
	_ = fs.Parse(args)

	if *agent == "" || *target == "" {
		fmt.Fprintln(os.Stderr, "usage: agentcage run --agent <path.cage> --target <host>")
		fmt.Fprintln(os.Stderr, "\nRequired:")
		fmt.Fprintln(os.Stderr, "  --agent       path to .cage bundle or agent directory")
		fmt.Fprintln(os.Stderr, "  --target      target host(s), comma-separated")
		fmt.Fprintln(os.Stderr, "\nOptional:")
		fmt.Fprintln(os.Stderr, "  --token-budget    LLM token budget")
		fmt.Fprintln(os.Stderr, "  --max-duration    assessment time limit")
		fmt.Fprintln(os.Stderr, "  --compliance      compliance framework")
		fmt.Fprintln(os.Stderr, "  --config          config YAML override")
		os.Exit(1)
	}

	targets := strings.Split(*target, ",")
	for i := range targets {
		targets[i] = strings.TrimSpace(targets[i])
	}

	fmt.Printf("Starting assessment...\n")
	fmt.Printf("  Agent:   %s\n", *agent)
	fmt.Printf("  Target:  %s\n", strings.Join(targets, ", "))
	if *tokenBudget > 0 {
		fmt.Printf("  Budget:  %d tokens\n", *tokenBudget)
	}
	if *maxDuration != "" {
		fmt.Printf("  Limit:   %s\n", *maxDuration)
	}
	if *compliance != "" {
		fmt.Printf("  Compliance: %s\n", *compliance)
	}
	if *config != "" {
		fmt.Printf("  Config:  %s\n", *config)
	}

	// TODO: Connect to orchestrator gRPC, upload .cage bundle, create assessment
	fmt.Println("\n(orchestrator gRPC client pending — T3 wiring)")
	fmt.Println("The assessment would be created via AssessmentService.CreateAssessment")
}
