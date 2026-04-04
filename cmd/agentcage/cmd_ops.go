package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/okedeji/agentcage/internal/config"
	"github.com/okedeji/agentcage/internal/embedded"
	"github.com/okedeji/agentcage/internal/enforcement"
)

var _ = cmdStop

// isProcessRunning checks whether a PID file exists and the process it
// references is still alive. Used to prevent launching a second instance.
func isProcessRunning(pidFile string) bool {
	data, err := os.ReadFile(pidFile)
	if err != nil {
		return false
	}
	var pid int
	if _, err := fmt.Sscanf(strings.TrimSpace(string(data)), "%d", &pid); err != nil {
		return false
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	return proc.Signal(syscall.Signal(0)) == nil
}

// killOrphanedServices finds PID files left by embedded services and sends
// SIGKILL to each. Called after the main agentcage process was force-killed
// and its normal shutdown sequence (which stops children gracefully) was skipped.
func killOrphanedServices() {
	runDir := embedded.RunDir()
	entries, err := os.ReadDir(runDir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".pid") || e.Name() == "agentcage.pid" {
			continue
		}
		pidPath := filepath.Join(runDir, e.Name())
		data, err := os.ReadFile(pidPath)
		if err != nil {
			continue
		}
		var pid int
		if _, err := fmt.Sscanf(strings.TrimSpace(string(data)), "%d", &pid); err != nil {
			continue
		}
		proc, err := os.FindProcess(pid)
		if err != nil {
			_ = os.Remove(pidPath)
			continue
		}
		if err := proc.Signal(syscall.Signal(0)); err != nil {
			_ = os.Remove(pidPath)
			continue
		}
		fmt.Fprintf(os.Stderr, "  killing orphaned service %s (pid %d)\n", strings.TrimSuffix(e.Name(), ".pid"), pid)
		_ = proc.Signal(syscall.SIGKILL)
		_ = os.Remove(pidPath)
	}
}

func cmdStop(_ []string) {
	pidFile := embedded.RunDir() + "/agentcage.pid"
	data, err := os.ReadFile(pidFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "agentcage is not running.")
		os.Exit(1)
	}

	var pid int
	if _, err := fmt.Sscanf(string(data), "%d", &pid); err != nil {
		fmt.Fprintf(os.Stderr, "invalid PID file: %v\n", err)
		os.Exit(1)
	}

	proc, err := os.FindProcess(pid)
	if err != nil {
		fmt.Fprintf(os.Stderr, "process %d not found: %v\n", pid, err)
		_ = os.Remove(pidFile)
		os.Exit(1)
	}

	// Check if process is actually alive before signaling
	if err := proc.Signal(syscall.Signal(0)); err != nil {
		fmt.Fprintln(os.Stderr, "agentcage is not running (stale PID file).")
		_ = os.Remove(pidFile)
		os.Exit(1)
	}

	if err := proc.Signal(syscall.SIGTERM); err != nil {
		fmt.Fprintf(os.Stderr, "failed to stop agentcage (pid %d): %v\n", pid, err)
		os.Exit(1)
	}

	fmt.Printf("Stopping agentcage (pid %d)...\n", pid)

	// Wait up to 10 seconds for the process to exit
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if err := proc.Signal(syscall.Signal(0)); err != nil {
			fmt.Println("agentcage stopped.")
			_ = os.Remove(pidFile)
			return
		}
		time.Sleep(250 * time.Millisecond)
	}

	// Process didn't exit in time — force kill and clean up child services
	fmt.Fprintf(os.Stderr, "agentcage did not stop within 10s, sending SIGKILL...\n")
	if err := proc.Signal(syscall.SIGKILL); err != nil {
		fmt.Fprintf(os.Stderr, "failed to kill agentcage (pid %d): %v\n", pid, err)
		os.Exit(1)
	}
	_ = os.Remove(pidFile)
	killOrphanedServices()
	fmt.Println("agentcage killed.")
}

func cmdTest(args []string) {
	fs := flag.NewFlagSet("test", flag.ExitOnError)
	agent := fs.String("agent", "", "path to .cage bundle or agent directory")
	target := fs.String("target", "", "single target endpoint")
	vulnClass := fs.String("vuln-class", "", "vulnerability class to test")
	followLogs := fs.Bool("follow-logs", false, "stream cage logs to terminal")
	_ = fs.Parse(args)

	if *agent == "" || *target == "" {
		fmt.Fprintln(os.Stderr, "usage: agentcage test --agent <path.cage> --target <endpoint> [--vuln-class sqli] [--follow-logs]")
		os.Exit(1)
	}

	fmt.Printf("Testing agent in single cage...\n")
	fmt.Printf("  Agent:     %s\n", *agent)
	fmt.Printf("  Target:    %s\n", *target)
	if *vulnClass != "" {
		fmt.Printf("  VulnClass: %s\n", *vulnClass)
	}
	fmt.Printf("  Logs:      %v\n", *followLogs)
	fmt.Println("\n(single cage creation via CageService.CreateCage pending)")
}

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

func cmdDB(args []string) {
	fs := flag.NewFlagSet("db", flag.ExitOnError)
	showURL := fs.Bool("url", false, "print connection string only")
	query := fs.String("query", "", "run a SQL query")
	_ = fs.Parse(args)

	dbURL, urlErr := embedded.PostgresURL()
	if urlErr != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", urlErr)
		os.Exit(1)
	}

	if *showURL {
		fmt.Println(dbURL)
		return
	}

	if _, err := exec.LookPath("psql"); err != nil {
		fmt.Fprintln(os.Stderr, "error: psql not found. Install it with: brew install libpq (macOS) or apt install postgresql-client (Linux)")
		os.Exit(1)
	}

	if *query != "" {
		psql := exec.Command("psql", dbURL, "-c", *query)
		psql.Stdout = os.Stdout
		psql.Stderr = os.Stderr
		if err := psql.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "error running query: %v\n", err)
			os.Exit(1)
		}
		return
	}

	// Open interactive psql
	fmt.Printf("Connecting to %s\n", dbURL)
	psql := exec.Command("psql", dbURL)
	psql.Stdin = os.Stdin
	psql.Stdout = os.Stdout
	psql.Stderr = os.Stderr
	if err := psql.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

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

