package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/nats-io/nats.go"

	pb "github.com/okedeji/agentcage/api/proto"
	"github.com/okedeji/agentcage/internal/cage"
	"github.com/okedeji/agentcage/internal/config"
	"github.com/okedeji/agentcage/internal/embedded"
)

var validServices = map[string]bool{
	"postgres":     true,
	"temporal":     true,
	"spire":        true,
	"vault":        true,
	"falco":        true,
	"nats":         true,
	"vm":           true,
	"orchestrator": true,
}

func cmdLogs(args []string) {
	fs := flag.NewFlagSet("logs", flag.ExitOnError)
	fs.Usage = printLogsUsage
	cageID := fs.String("cage", "", "cage ID to stream logs from")
	service := fs.String("service", "", "service log: postgres, temporal, spire, vault, falco, nats")
	assessmentID := fs.String("assessment", "", "tail logs for all cages in an assessment")
	follow := fs.Bool("follow", false, "stream live logs (running cages only)")
	lines := fs.Int("lines", 0, "show last N lines before streaming")
	format := fs.String("format", "text", "output format: text (human-readable) or json (raw)")
	_ = fs.Parse(args)

	if *service != "" {
		tailServiceLog(*service, *follow, *lines, *format)
		return
	}

	if *cageID != "" {
		handleCageLogs(*cageID, *follow, *lines)
		return
	}

	if *assessmentID != "" {
		tailAssessmentLogs(*assessmentID, *follow, *lines)
		return
	}

	printLogsUsage()
}

func tailServiceLog(service string, follow bool, tailLines int, format string) {
	if !validServices[service] {
		fmt.Fprintf(os.Stderr, "error: unknown service %q (valid: %s)\n", service, strings.Join(serviceNames(), ", "))
		os.Exit(1)
	}

	var logFile string
	switch service {
	case "vm":
		logFile = filepath.Join(config.HomeDir(), "vm-console.log")
	case "orchestrator":
		logFile = filepath.Join(embedded.LogDir(), "orchestrator.log")
	default:
		logFile = filepath.Join(embedded.LogDir(), service+".log")
	}
	if _, err := os.Stat(logFile); os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "no log file for service %s\n", service)
		os.Exit(1)
	}

	if _, err := exec.LookPath("tail"); err != nil {
		fmt.Fprintln(os.Stderr, "error: tail not found on PATH")
		os.Exit(1)
	}

	var tailArgs []string
	if follow {
		tailArgs = append(tailArgs, "-f")
	}
	if tailLines > 0 {
		tailArgs = append(tailArgs, "-n", fmt.Sprintf("%d", tailLines))
	} else if !follow {
		tailArgs = append(tailArgs, "-n", "+1")
	}
	tailArgs = append(tailArgs, logFile)

	fmt.Printf("Tailing %s logs...\n", service)
	tail := exec.Command("tail", tailArgs...)
	tail.Stderr = os.Stderr
	tail.Stdin = os.Stdin

	if format == "json" {
		tail.Stdout = os.Stdout
	} else {
		// Pipe through formatter for human-readable output.
		stdout, err := tail.StdoutPipe()
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		go formatLogLines(stdout)
	}

	if err := tail.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func handleCageLogs(cageID string, follow bool, tailLines int) {
	if strings.Contains(cageID, "/") || strings.Contains(cageID, "\\") || strings.Contains(cageID, "..") {
		fmt.Fprintln(os.Stderr, "error: invalid cage ID")
		os.Exit(1)
	}

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

	client := pb.NewCageServiceClient(conn)
	resp, err := client.GetCageLogs(ctx, &pb.GetCageLogsRequest{
		CageId:    cageID,
		TailLines: int32(tailLines),
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	isRunning := resp.GetIsRunning()

	// Print historical/current lines
	for _, line := range resp.GetLines() {
		fmt.Println(line)
	}

	if !follow {
		return
	}

	if !isRunning {
		fmt.Fprintln(os.Stderr, "Cage has completed. Logs are static.")
		return
	}

	// Live streaming via NATS
	nc, err := nats.Connect(embedded.NATSURL())
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: connecting to NATS for live streaming: %v\n", err)
		os.Exit(1)
	}
	defer nc.Close()

	subject := cage.LogSubject(cageID)
	fmt.Fprintf(os.Stderr, "Streaming live logs for cage %s (Ctrl+C to stop)...\n", cageID)

	msgCh := make(chan *nats.Msg, 256)
	sub, err := nc.ChanSubscribe(subject, msgCh)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: subscribing to %s: %v\n", subject, err)
		os.Exit(1)
	}
	defer func() { _ = sub.Unsubscribe() }()

	pollTicker := time.NewTicker(5 * time.Second)
	defer pollTicker.Stop()

	for {
		select {
		case msg, ok := <-msgCh:
			if !ok {
				return
			}
			fmt.Println(string(msg.Data))
		case <-pollTicker.C:
			pollCtx, pollCancel := context.WithTimeout(context.Background(), 10*time.Second)
			checkResp, checkErr := client.GetCageLogs(pollCtx, &pb.GetCageLogsRequest{CageId: cageID, TailLines: 0})
			pollCancel()
			if checkErr == nil && !checkResp.GetIsRunning() {
				fmt.Fprintln(os.Stderr, "\nCage completed. Stream ended.")
				return
			}
		}
	}
}

func tailAssessmentLogs(assessmentID string, follow bool, tailLines int) {
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
	var tailArgs []string
	if follow {
		tailArgs = append(tailArgs, "-f")
	}
	if tailLines > 0 {
		tailArgs = append(tailArgs, "-n", fmt.Sprintf("%d", tailLines))
	} else if !follow {
		tailArgs = append(tailArgs, "-n", "+1")
	}
	tailArgs = append(tailArgs, logFiles...)
	tail := exec.Command("tail", tailArgs...)
	tail.Stdout = os.Stdout
	tail.Stderr = os.Stderr
	tail.Stdin = os.Stdin
	if err := tail.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

// formatLogLines reads JSON log lines from r and prints them as
// human-readable text: "timestamp LEVEL message key=value ..."
func formatLogLines(r io.Reader) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		var entry map[string]any
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			// Not JSON — print as-is (UI output, plain text lines).
			fmt.Println(line)
			continue
		}

		// Extract standard fields.
		ts := extractString(entry, "ts", "time", "timestamp", "T")
		level := strings.ToUpper(extractString(entry, "level", "L"))
		msg := extractString(entry, "msg", "message", "M")
		caller := extractString(entry, "caller")

		// Format timestamp.
		if tsFloat, ok := entry["ts"].(float64); ok {
			sec := int64(tsFloat)
			nsec := int64((tsFloat - float64(sec)) * 1e9)
			t := time.Unix(sec, nsec).Local()
			ts = t.Format("15:04:05.000")
			delete(entry, "ts")
		} else if ts != "" {
			if t, err := time.Parse(time.RFC3339Nano, ts); err == nil {
				ts = t.Local().Format("15:04:05.000")
			} else if t, err := time.Parse("2006-01-02T15:04:05.000Z", ts); err == nil {
				ts = t.Local().Format("15:04:05.000")
			}
		}

		// Remove already-printed fields.
		delete(entry, "level")
		delete(entry, "L")
		delete(entry, "msg")
		delete(entry, "message")
		delete(entry, "M")
		delete(entry, "time")
		delete(entry, "timestamp")
		delete(entry, "T")
		delete(entry, "caller")

		// Build key=value pairs from remaining fields.
		var extra []string
		keys := make([]string, 0, len(entry))
		for k := range entry {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			v := entry[k]
			extra = append(extra, fmt.Sprintf("%s=%v", k, v))
		}

		// Color the level.
		levelColored := level
		switch level {
		case "INFO":
			levelColored = "\033[36mINFO\033[0m"
		case "WARN", "WARNING":
			levelColored = "\033[33mWARN\033[0m"
		case "ERROR":
			levelColored = "\033[31mERRO\033[0m"
		case "DEBUG":
			levelColored = "\033[90mDEBG\033[0m"
		}

		// Print formatted line.
		out := fmt.Sprintf("%s %s %s", ts, levelColored, msg)
		if caller != "" {
			out += fmt.Sprintf(" \033[90m(%s)\033[0m", caller)
		}
		if len(extra) > 0 {
			out += " \033[90m" + strings.Join(extra, " ") + "\033[0m"
		}
		fmt.Println(out)
	}
}

func extractString(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if v, ok := m[k]; ok {
			if s, ok := v.(string); ok {
				return s
			}
		}
	}
	return ""
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
       agentcage logs --cage <cage-id> [--lines N]
       agentcage logs --cage <cage-id> --follow [--lines N]
       agentcage logs --assessment <assessment-id>

Stream logs from services or cages.

For running cages, --follow streams live via NATS.
For completed cages, logs are read from the orchestrator's local store.
Use --lines N to show the last N lines before streaming.

Examples:
  agentcage logs --service postgres
  agentcage logs --cage <cage-id>
  agentcage logs --cage <cage-id> --lines 100
  agentcage logs --cage <cage-id> --follow
  agentcage logs --cage <cage-id> --follow --lines 50
  agentcage logs --assessment <assessment-id>

Flags:
  --service      service log: orchestrator, postgres, temporal, spire, vault, falco, nats, vm
  --cage         cage ID to stream logs from
  --assessment   tail logs for all cages in an assessment
  --follow       stream live logs (running cages only)
  --lines N      show last N lines (0 = all)
  --format       output format: text (default, human-readable) or json (raw)
`)
}
