package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"

	"github.com/okedeji/agentcage/internal/embedded"
)

func cmdLogs(args []string) {
	fs := flag.NewFlagSet("logs", flag.ExitOnError)
	cageID := fs.String("cage", "", "cage ID to stream logs from")
	service := fs.String("service", "", "service log: postgres, temporal, spire, vault, falco")
	_ = fs.Parse(args)

	if *service != "" {
		logFile := embedded.LogDir() + "/" + *service + ".log"
		if _, err := os.Stat(logFile); os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "no log file for service %s\n", *service)
			os.Exit(1)
		}
		fmt.Printf("Tailing %s logs (%s)...\n", *service, logFile)
		tail := exec.Command("tail", "-f", logFile)
		tail.Stdout = os.Stdout
		tail.Stderr = os.Stderr
		_ = tail.Run()
		return
	}

	if *cageID != "" {
		fmt.Printf("Streaming logs for cage %s...\n", *cageID)
		fmt.Println("  (requires vsock connection — pending)")
		return
	}

	fmt.Println("usage: agentcage logs --service <name> | --cage <cage-id>")
	fmt.Println("\nServices: postgres, temporal, spire, vault, falco")
}
