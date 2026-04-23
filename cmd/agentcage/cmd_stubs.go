package main

import (
	"fmt"
	"os"
)

// Commands below are placeholders until the shared gRPC CLI client
// lands. Each parses its flags so --help works, then exits with a
// pending message. On darwin these are unreachable for proxy commands
// (fleet) because isProxyCommand routes them through
// internal/grpc.Proxy instead.

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
