package main

import (
	"fmt"
	"os"
)

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
