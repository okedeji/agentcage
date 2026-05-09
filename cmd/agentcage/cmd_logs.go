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

func cmdLogs(args []string) {
	if len(args) == 0 {
		printLogsUsage()
		os.Exit(1)
	}

	source := args[0]
	rest := args[1:]

	switch source {
	case "orchestrator", "postgres", "temporal", "spire", "vault", "falco", "nats", "firecracker":
		cmdLogsService(source, rest)
	case "cage":
		cmdLogsCage(rest)
	case "assessment":
		cmdLogsAssessment(rest)
	default:
		fmt.Fprintf(os.Stderr, "unknown log source: %s\n\n", source)
		printLogsUsage()
		os.Exit(1)
	}
}

func cmdLogsService(service string, args []string) {
	fs := flag.NewFlagSet("logs "+service, flag.ExitOnError)
	follow := fs.Bool("follow", false, "stream live")
	followShort := fs.Bool("f", false, "stream live (short)")
	lines := fs.Int("lines", 0, "show last N lines")
	format := fs.String("format", "text", "output format: text or json")
	vmm := fs.Bool("vmm", false, "show VMM trace log instead of serial output (firecracker only)")
	_ = fs.Parse(args)

	if *followShort {
		*follow = true
	}

	var logFile string
	switch service {
	case "orchestrator":
		logFile = filepath.Join(embedded.LogDir(), "orchestrator.log")
	case "firecracker":
		if *vmm {
			logFile = filepath.Join(embedded.LogDir(), "firecracker-vmm.log")
		} else {
			logFile = filepath.Join(embedded.LogDir(), "firecracker.log")
		}
	default:
		logFile = filepath.Join(embedded.LogDir(), service+".log")
	}
	if _, err := os.Stat(logFile); os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "no log file for %s\n", service)
		os.Exit(1)
	}

	var tailArgs []string
	if *follow {
		tailArgs = append(tailArgs, "-f")
	}
	if *lines > 0 {
		tailArgs = append(tailArgs, "-n", fmt.Sprintf("%d", *lines))
	} else if !*follow {
		tailArgs = append(tailArgs, "-n", "+1")
	}
	tailArgs = append(tailArgs, logFile)

	tail := exec.Command("tail", tailArgs...)
	tail.Stderr = os.Stderr
	tail.Stdin = os.Stdin

	if *format == "json" {
		tail.Stdout = os.Stdout
	} else {
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

func cmdLogsCage(args []string) {
	fs := flag.NewFlagSet("logs cage", flag.ExitOnError)
	source := fs.String("source", "", "filter by source: agent, cage-init")
	follow := fs.Bool("follow", false, "stream live")
	followShort := fs.Bool("f", false, "stream live (short)")
	lines := fs.Int("lines", 0, "show last N lines")
	_ = fs.Parse(reorderArgs(args))

	if *followShort {
		*follow = true
	}

	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "usage: agentcage logs cage <id> [--source agent|cage-init] [--follow]")
		os.Exit(1)
	}
	cageID := fs.Arg(0)

	if strings.ContainsAny(cageID, "/\\..") {
		fmt.Fprintln(os.Stderr, "error: invalid cage ID")
		os.Exit(1)
	}

	cfg := loadClientConfig()
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
		TailLines: int32(*lines),
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	for _, line := range resp.GetLines() {
		if *source != "" && !strings.Contains(line, "["+*source+"]") {
			continue
		}
		fmt.Println(line)
	}

	if !*follow {
		return
	}

	if !resp.GetIsRunning() {
		fmt.Fprintln(os.Stderr, "Cage has completed. Logs are static.")
		return
	}

	nc, err := nats.Connect(embedded.NATSURL())
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: connecting to NATS: %v\n", err)
		os.Exit(1)
	}
	defer nc.Close()

	subject := cage.LogSubject(cageID)
	fmt.Fprintf(os.Stderr, "Streaming live logs (Ctrl+C to stop)...\n")

	msgCh := make(chan *nats.Msg, 256)
	sub, err := nc.ChanSubscribe(subject, msgCh)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: subscribing: %v\n", err)
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
			line := string(msg.Data)
			if *source != "" && !strings.Contains(line, "["+*source+"]") {
				continue
			}
			fmt.Println(line)
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

func cmdLogsAssessment(args []string) {
	fs := flag.NewFlagSet("logs assessment", flag.ExitOnError)
	follow := fs.Bool("follow", false, "stream live")
	followShort := fs.Bool("f", false, "stream live (short)")
	lines := fs.Int("lines", 0, "show last N lines")
	_ = fs.Parse(reorderArgs(args))

	if *followShort {
		*follow = true
	}

	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "usage: agentcage logs assessment <id> [--follow]")
		os.Exit(1)
	}
	assessmentID := fs.Arg(0)

	cfg := loadClientConfig()
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
		fmt.Printf("No log files for assessment %s (%d cages, no logs on disk).\n", assessmentID, len(cageIDs))
		return
	}

	var tailArgs []string
	if *follow {
		tailArgs = append(tailArgs, "-f")
	}
	if *lines > 0 {
		tailArgs = append(tailArgs, "-n", fmt.Sprintf("%d", *lines))
	} else if !*follow {
		tailArgs = append(tailArgs, "-n", "+1")
	}
	tailArgs = append(tailArgs, logFiles...)

	fmt.Printf("Tailing %d cage log(s) for assessment %s...\n", len(logFiles), assessmentID)
	tail := exec.Command("tail", tailArgs...)
	tail.Stdout = os.Stdout
	tail.Stderr = os.Stderr
	tail.Stdin = os.Stdin
	if err := tail.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func loadClientConfig() *config.Config {
	cfg := config.Defaults()
	if resolved := config.Resolve(""); resolved != "" {
		if override, err := config.Load(resolved); err == nil {
			cfg = config.Merge(cfg, override)
		}
	}
	return cfg
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
			fmt.Println(line)
			continue
		}

		ts := extractString(entry, "ts", "time", "timestamp", "T")
		level := strings.ToUpper(extractString(entry, "level", "L"))
		msg := extractString(entry, "msg", "message", "M")
		caller := extractString(entry, "caller")

		if tsFloat, ok := entry["ts"].(float64); ok {
			sec := int64(tsFloat)
			nsec := int64((tsFloat - float64(sec)) * 1e9)
			t := time.Unix(sec, nsec).Local()
			ts = t.Format("15:04:05.000")
			delete(entry, "ts")
		} else if ts != "" {
			if t, err := time.Parse(time.RFC3339Nano, ts); err == nil {
				ts = t.Local().Format("15:04:05.000")
			}
		}

		delete(entry, "level")
		delete(entry, "L")
		delete(entry, "msg")
		delete(entry, "message")
		delete(entry, "M")
		delete(entry, "time")
		delete(entry, "timestamp")
		delete(entry, "T")
		delete(entry, "caller")

		var extra []string
		keys := make([]string, 0, len(entry))
		for k := range entry {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			extra = append(extra, fmt.Sprintf("%s=%v", k, entry[k]))
		}

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

func printLogsUsage() {
	fmt.Fprintf(os.Stderr, `Usage: agentcage logs <source> [id] [flags]

View logs from any agentcage component.

Sources:
  orchestrator              Orchestrator structured logs
  postgres                  PostgreSQL subprocess output
  temporal                  Temporal workflow engine output
  spire                     SPIRE identity service output
  vault                     Vault secrets manager output
  falco                     Falco runtime security output
  nats                      NATS message broker output
  firecracker               Firecracker VM output (kernel boot, cage-init, sidecars)
  cage <id>                 Cage logs (agent + cage-init)
  assessment <id>           All cage logs for an assessment

Common flags:
  --follow, -f              Stream live logs
  --lines N                 Show last N lines
  --format text|json        Output format (services only)

Cage-specific flags:
  --source agent|cage-init  Filter cage logs by source

Examples:
  agentcage logs orchestrator
  agentcage logs orchestrator -f
  agentcage logs falco --lines 50
  agentcage logs cage <id>
  agentcage logs cage <id> --source agent
  agentcage logs cage <id> --source agent -f
  agentcage logs assessment <id>
`)
}
