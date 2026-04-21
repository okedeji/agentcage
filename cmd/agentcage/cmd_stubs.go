package main

import (
	"flag"
	"fmt"
	"os"
)

// Commands below are placeholders until the shared gRPC CLI client
// lands. Each parses its flags so --help works, then exits with a
// pending message. On darwin these are unreachable for proxy commands
// (run/status/interventions/resolve/fleet) because
// isProxyCommand routes them through internal/grpc.Proxy instead.

func cmdStatus(args []string) {
	_ = args
	fmt.Println("Assessment status:")
	fmt.Println("  (requires connection to orchestrator gRPC — pending)")
}

func cmdFindings(args []string) {
	fs := flag.NewFlagSet("findings", flag.ExitOnError)
	assessmentID := fs.String("assessment", "", "assessment ID")
	severity := fs.String("severity", "", "filter by severity (critical,high,medium,low,info)")
	_ = fs.Parse(args)

	fmt.Printf("Findings")
	if *assessmentID != "" {
		fmt.Printf(" for assessment %s", *assessmentID)
	}
	if *severity != "" {
		fmt.Printf(" (severity: %s)", *severity)
	}
	fmt.Println(":")
	fmt.Println("  (requires connection to orchestrator gRPC — pending)")
}

func cmdReport(args []string) {
	fs := flag.NewFlagSet("report", flag.ExitOnError)
	assessmentID := fs.String("assessment", "", "assessment ID")
	format := fs.String("format", "text", "output format: text, json")
	_ = fs.Parse(args)

	fmt.Printf("Report (format=%s)", *format)
	if *assessmentID != "" {
		fmt.Printf(" for assessment %s", *assessmentID)
	}
	fmt.Println(":")
	fmt.Println("  (requires connection to orchestrator gRPC — pending)")
}

func cmdInterventions(args []string) {
	fs := flag.NewFlagSet("interventions", flag.ExitOnError)
	status := fs.String("status", "pending", "filter by status: pending, resolved, timed_out")
	_ = fs.Parse(args)

	fmt.Printf("Interventions (status=%s):\n", *status)
	fmt.Println("  (requires connection to orchestrator gRPC — pending)")
}

func cmdResolve(args []string) {
	fs := flag.NewFlagSet("resolve", flag.ExitOnError)
	interventionID := fs.String("id", "", "intervention ID")
	action := fs.String("action", "", "action: resume, kill, allow, block")
	rationale := fs.String("rationale", "", "reason for the decision")
	_ = fs.Parse(args)

	if *interventionID == "" || *action == "" {
		fmt.Fprintln(os.Stderr, "usage: agentcage resolve --id <intervention-id> --action <resume|kill|allow|block> [--rationale reason]")
		os.Exit(1)
	}

	fmt.Printf("Resolving intervention %s with action=%s\n", *interventionID, *action)
	if *rationale != "" {
		fmt.Printf("  Rationale: %s\n", *rationale)
	}
	fmt.Println("  (requires connection to orchestrator gRPC — pending)")
}

func cmdFleet(args []string) {
	_ = args
	fmt.Println("Fleet status:")
	fmt.Println("  (requires connection to orchestrator gRPC — pending)")
}

func cmdAudit(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: agentcage audit verify <cage-id>")
		os.Exit(1)
	}

	switch args[0] {
	case "verify":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "usage: agentcage audit verify <cage-id>")
			os.Exit(1)
		}
		cageID := args[1]
		fmt.Printf("Verifying audit chain for cage %s...\n", cageID)
		fmt.Println("  (requires audit store connection — pending)")

	default:
		fmt.Fprintf(os.Stderr, "unknown audit subcommand: %s\n", args[0])
		fmt.Fprintln(os.Stderr, "usage: agentcage audit verify <cage-id>")
		os.Exit(1)
	}
}
