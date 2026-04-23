package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	pb "github.com/okedeji/agentcage/api/proto"
	"github.com/okedeji/agentcage/internal/config"
	"github.com/okedeji/agentcage/internal/embedded"
)

var validServices = map[string]bool{
	"postgres": true,
	"temporal": true,
	"spire":    true,
	"vault":    true,
	"falco":    true,
	"nats":     true,
}

func cmdLogs(args []string) {
	fs := flag.NewFlagSet("logs", flag.ExitOnError)
	fs.Usage = printLogsUsage
	cageID := fs.String("cage", "", "cage ID to stream logs from")
	service := fs.String("service", "", "service log: postgres, temporal, spire, vault, falco, nats")
	assessmentID := fs.String("assessment", "", "tail logs for all cages in an assessment")
	_ = fs.Parse(args)

	if *service != "" {
		tailServiceLog(*service)
		return
	}

	if *cageID != "" {
		tailCageLog(*cageID)
		return
	}

	if *assessmentID != "" {
		tailAssessmentLogs(*assessmentID)
		return
	}

	printLogsUsage()
}

func tailServiceLog(service string) {
	if !validServices[service] {
		fmt.Fprintf(os.Stderr, "error: unknown service %q (valid: %s)\n", service, strings.Join(serviceNames(), ", "))
		os.Exit(1)
	}

	logFile := filepath.Join(embedded.LogDir(), service+".log")
	if _, err := os.Stat(logFile); os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "no log file for service %s\n", service)
		os.Exit(1)
	}

	fmt.Printf("Tailing %s logs...\n", service)
	runTail(logFile)
}

func tailCageLog(cageID string) {
	if strings.Contains(cageID, "/") || strings.Contains(cageID, "\\") || strings.Contains(cageID, "..") {
		fmt.Fprintln(os.Stderr, "error: invalid cage ID")
		os.Exit(1)
	}

	cageLogDir := filepath.Join(embedded.DataDir(), "cage-logs")
	logFile := filepath.Join(cageLogDir, cageID+".log")
	if _, err := os.Stat(logFile); os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "no logs for cage %s\n", cageID)
		fmt.Fprintln(os.Stderr, "  the cage may not have started or log forwarding is not connected")
		os.Exit(1)
	}

	fmt.Printf("Tailing cage %s logs...\n", cageID)
	runTail(logFile)
}

func tailAssessmentLogs(assessmentID string) {
	cfg := config.Defaults()
	if resolved := config.Resolve(""); resolved != "" {
		override, err := config.Load(resolved)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: loading config: %v\n", err)
			os.Exit(1)
		}
		cfg = config.Merge(cfg, override)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := dialOrchestrator(ctx, cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	defer func() { _ = conn.Close() }()

	cageClient := pb.NewCageServiceClient(conn)
	resp, err := cageClient.ListCagesByAssessment(ctx, &pb.ListCagesByAssessmentRequest{AssessmentId: assessmentID})
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	cageIDs := resp.GetCageIds()
	if len(cageIDs) == 0 {
		fmt.Printf("No cages found for assessment %s.\n", assessmentID)
		return
	}

	cageLogDir := filepath.Join(embedded.DataDir(), "cage-logs")
	var logFiles []string
	for _, id := range cageIDs {
		logFile := filepath.Join(cageLogDir, id+".log")
		if _, err := os.Stat(logFile); err == nil {
			logFiles = append(logFiles, logFile)
		}
	}

	if len(logFiles) == 0 {
		fmt.Printf("No cage log files found for assessment %s (%d cages, no logs on disk).\n", assessmentID, len(cageIDs))
		return
	}

	if _, err := exec.LookPath("tail"); err != nil {
		fmt.Fprintln(os.Stderr, "error: tail not found on PATH")
		os.Exit(1)
	}

	fmt.Printf("Tailing %d cage log files for assessment %s...\n", len(logFiles), assessmentID)
	tailArgs := append([]string{"-f"}, logFiles...)
	tail := exec.Command("tail", tailArgs...)
	tail.Stdout = os.Stdout
	tail.Stderr = os.Stderr
	tail.Stdin = os.Stdin
	if err := tail.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func runTail(logFile string) {
	if _, err := exec.LookPath("tail"); err != nil {
		fmt.Fprintln(os.Stderr, "error: tail not found on PATH")
		os.Exit(1)
	}
	tail := exec.Command("tail", "-f", logFile)
	tail.Stdout = os.Stdout
	tail.Stderr = os.Stderr
	tail.Stdin = os.Stdin
	if err := tail.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func serviceNames() []string {
	names := make([]string, 0, len(validServices))
	for name := range validServices {
		names = append(names, name)
	}
	return names
}

func printLogsUsage() {
	fmt.Fprintf(os.Stderr, `usage: agentcage logs --service <name>
       agentcage logs --cage <cage-id>
       agentcage logs --assessment <assessment-id>

Stream logs from services or cages.

Examples:
  agentcage logs --service postgres
  agentcage logs --cage <cage-id>
  agentcage logs --assessment <assessment-id>

Flags:
  --service      service log: postgres, temporal, spire, vault, falco, nats
  --cage         cage ID to stream logs from
  --assessment   tail logs for all cages in an assessment
`)
}
