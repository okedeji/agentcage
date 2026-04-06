package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
)

// stringSliceFlag is a repeatable string flag (e.g. --hint a --hint b).
type stringSliceFlag []string

func (s *stringSliceFlag) String() string     { return strings.Join(*s, ",") }
func (s *stringSliceFlag) Set(v string) error { *s = append(*s, v); return nil }

func cmdRun(args []string) {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	agent := fs.String("agent", "", "path to .cage bundle or agent directory")
	target := fs.String("target", "", "target host(s), comma-separated")
	tokenBudget := fs.Int64("token-budget", 0, "LLM token budget (default: from config)")
	maxDuration := fs.String("max-duration", "", "assessment time limit (e.g. 30m, 4h)")
	compliance := fs.String("compliance", "", "compliance framework (soc2, hipaa, pci_dss)")
	config := fs.String("config", "", "path to config YAML override file")

	// Guidance flags (pre-run hints to bias the coordinator)
	hintContext := fs.String("hint", "", "free-text context for the LLM coordinator")
	guidanceFile := fs.String("guidance-file", "", "path to YAML guidance file (alternative to flags)")
	requirePoC := fs.Bool("require-poc", false, "require working PoC for every finding")
	headlessXSS := fs.Bool("headless-xss", false, "use headless browser for XSS validation")
	var focusVuln, endpoints, deprioritize, knownWeaknesses, apiSpecs stringSliceFlag
	fs.Var(&focusVuln, "focus", "vuln class to prioritize (repeatable)")
	fs.Var(&endpoints, "endpoint", "endpoint to focus on (repeatable)")
	fs.Var(&deprioritize, "avoid", "path to deprioritize (repeatable)")
	fs.Var(&knownWeaknesses, "known-weakness", "known weakness description (repeatable)")
	fs.Var(&apiSpecs, "api-spec", "URL to OpenAPI/GraphQL spec (repeatable)")

	_ = fs.Parse(args)

	if *agent == "" || *target == "" {
		fmt.Fprintln(os.Stderr, "usage: agentcage run --agent <path.cage> --target <host>")
		fmt.Fprintln(os.Stderr, "\nRequired:")
		fmt.Fprintln(os.Stderr, "  --agent       path to .cage bundle or agent directory")
		fmt.Fprintln(os.Stderr, "  --target      target host(s), comma-separated")
		fmt.Fprintln(os.Stderr, "\nOptional:")
		fmt.Fprintln(os.Stderr, "  --token-budget       LLM token budget")
		fmt.Fprintln(os.Stderr, "  --max-duration       assessment time limit")
		fmt.Fprintln(os.Stderr, "  --compliance         compliance framework")
		fmt.Fprintln(os.Stderr, "  --config             config YAML override")
		fmt.Fprintln(os.Stderr, "\nGuidance (optional, biases the coordinator):")
		fmt.Fprintln(os.Stderr, "  --hint               free-text context for the LLM coordinator")
		fmt.Fprintln(os.Stderr, "  --focus              vuln class to prioritize (repeatable)")
		fmt.Fprintln(os.Stderr, "  --endpoint           endpoint to focus on (repeatable)")
		fmt.Fprintln(os.Stderr, "  --avoid              path to deprioritize (repeatable)")
		fmt.Fprintln(os.Stderr, "  --known-weakness     known weakness description (repeatable)")
		fmt.Fprintln(os.Stderr, "  --api-spec           URL to OpenAPI/GraphQL spec (repeatable)")
		fmt.Fprintln(os.Stderr, "  --require-poc        require working PoC for every finding")
		fmt.Fprintln(os.Stderr, "  --headless-xss       use headless browser for XSS validation")
		fmt.Fprintln(os.Stderr, "  --guidance-file      path to YAML guidance file (alternative to flags)")
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
	if *hintContext != "" || len(focusVuln) > 0 || len(endpoints) > 0 || *guidanceFile != "" {
		fmt.Println("  Guidance: provided")
	}

	// TODO: Connect to orchestrator gRPC, upload .cage bundle, create assessment.
	// When wired, build assessment.Config.Guidance from flags or guidance-file
	// and send via AssessmentService.CreateAssessment.
	_ = requirePoC
	_ = headlessXSS
	_ = deprioritize
	_ = knownWeaknesses
	_ = apiSpecs

	fmt.Println("\n(orchestrator gRPC client pending — T3 wiring)")
	fmt.Println("The assessment would be created via AssessmentService.CreateAssessment")
}
