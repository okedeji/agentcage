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

	pb "github.com/okedeji/agentcage/api/proto"
	"github.com/okedeji/agentcage/internal/config"
	"github.com/okedeji/agentcage/internal/embedded"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func cmdLogs(args []string) {
	if len(args) == 0 {
		printLogsUsage()
		os.Exit(1)
	}

	source := args[0]
	rest := args[1:]

	switch source {
	case "orchestrator", "postgres", "temporal", "spire", "vault", "falco", "nats":
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
	_ = fs.Parse(args)

	if *followShort {
		*follow = true
	}

	// Remote: fetch or stream logs via gRPC.
	cfg := loadClientConfig()
	if cfg.ServerAddress() != "" {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		conn, err := dialOrchestrator(ctx, cfg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		defer func() { _ = conn.Close() }()

		svcName := service

		tailLines := int32(200)
		if *lines > 0 {
			tailLines = int32(*lines)
		}

		client := pb.NewControlServiceClient(conn)

		if *follow {
			stream, err := client.StreamServiceLog(ctx, &pb.StreamServiceLogRequest{
				Service:   svcName,
				TailLines: tailLines,
			})
			if err != nil {
				fmt.Fprintf(os.Stderr, "error: %v\n", err)
				os.Exit(1)
			}
			for {
				resp, err := stream.Recv()
				if err != nil {
					return
				}
				if *format == "json" {
					fmt.Println(resp.GetLine())
				} else {
					r := strings.NewReader(resp.GetLine() + "\n")
					formatLogLines(r)
				}
			}
		}

		resp, err := client.GetServiceLog(ctx, &pb.GetServiceLogRequest{
			Service:   svcName,
			TailLines: tailLines,
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}

		if *format == "json" {
			for _, line := range resp.GetLines() {
				fmt.Println(line)
			}
		} else {
			r := strings.NewReader(strings.Join(resp.GetLines(), "\n") + "\n")
			formatLogLines(r)
		}
		return
	}

	// Local: tail the log file directly.
	var logFile string
	switch service {
	case "orchestrator":
		logFile = filepath.Join(embedded.LogDir(), "orchestrator.log")
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
	source := fs.String("source", "", "filter by source: agent, system")
	follow := fs.Bool("follow", false, "stream live")
	followShort := fs.Bool("f", false, "stream live (short)")
	lines := fs.Int("lines", 0, "show last N lines")
	format := fs.String("format", "text", "output format: text or json")
	_ = fs.Parse(reorderArgs(args))

	if *followShort {
		*follow = true
	}

	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "usage: agentcage logs cage <id> [--source agent|system] [--follow]")
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
		Serial:    *source == "infra",
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	for _, line := range resp.GetLines() {
		if *source != "" && !strings.Contains(line, `"source":"`+*source+`"`) {
			continue
		}
		if *format == "json" {
			fmt.Println(line)
		} else {
			fmt.Println(formatCageLogLine(line))
		}
	}

	if !*follow {
		return
	}

	if !resp.GetIsRunning() {
		fmt.Fprintln(os.Stderr, "Cage has completed. Logs are static.")
		return
	}

	// Stream via the server-streaming RPC. Falls back to polling
	// if the server is too old to support StreamCageLogs.
	fmt.Fprintf(os.Stderr, "Streaming live logs (Ctrl+C to stop)...\n")

	streamCtx, streamCancel := context.WithCancel(context.Background())
	defer streamCancel()

	stream, err := client.StreamCageLogs(streamCtx, &pb.StreamCageLogsRequest{
		CageId:       cageID,
		TailLines:    0, // historical already printed above
		SourceFilter: *source,
	})
	if err != nil {
		if status.Code(err) == codes.Unimplemented {
			pollCageLogs(client, cageID, *source, int32(len(resp.GetLines())))
			return
		}
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	for {
		msg, err := stream.Recv()
		if err == io.EOF {
			return
		}
		if err != nil {
			if streamCtx.Err() != nil {
				return
			}
			fmt.Fprintf(os.Stderr, "\nstream error: %v\n", err)
			return
		}
		if msg.GetCompleted() {
			fmt.Fprintf(os.Stderr, "\nCage %s.\n", msg.GetCageState())
			return
		}
		if *format == "json" {
			fmt.Println(msg.GetLine())
		} else {
			fmt.Println(formatCageLogLine(msg.GetLine()))
		}
	}
}

// pollCageLogs is the fallback for servers that don't support StreamCageLogs.
func pollCageLogs(client pb.CageServiceClient, cageID, source string, lastCount int32) {
	for {
		time.Sleep(3 * time.Second)
		pollCtx, pollCancel := context.WithTimeout(context.Background(), 10*time.Second)
		resp, err := client.GetCageLogs(pollCtx, &pb.GetCageLogsRequest{CageId: cageID, TailLines: 0})
		pollCancel()
		if err != nil {
			continue
		}
		lines := resp.GetLines()
		for i := lastCount; i < int32(len(lines)); i++ {
			line := lines[i]
			if source != "" && !strings.Contains(line, `"source":"`+source+`"`) {
				continue
			}
			fmt.Println(line)
		}
		lastCount = int32(len(lines))
		if !resp.GetIsRunning() {
			fmt.Fprintln(os.Stderr, "\nCage completed.")
			return
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

// formatCageLogLine parses a cage JSON log line into human-readable
// text. Handles both raw JSON from CollectCageLogs and the
// "[source] {json}" format from the FileSink/NATS stream.
func formatCageLogLine(line string) string {
	// Strip FileSink "[source] " prefix if present.
	if idx := strings.Index(line, "] {"); idx > 0 && line[0] == '[' {
		line = line[idx+2:]
	}

	var entry struct {
		Source string  `json:"source"`
		Msg    string  `json:"msg"`
		Ts     float64 `json:"ts"`
	}
	if err := json.Unmarshal([]byte(line), &entry); err != nil {
		return line
	}

	ts := time.Unix(int64(entry.Ts), 0).Local().Format("15:04:05")
	source := entry.Source
	if source == "" {
		source = "system"
	}
	return fmt.Sprintf("%s [%s] %s", ts, source, entry.Msg)
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
  cage <id>                 Cage logs (agent + system)
  assessment <id>           All cage logs for an assessment

Common flags:
  --follow, -f              Stream live logs
  --lines N                 Show last N lines
  --format text|json        Output format (services only)

Cage-specific flags:
  --source agent|system|infra  Filter cage logs by source
           agent               Agent process output
           system              Cage lifecycle events (start, stop, errors)
           infra               VM serial console (kernel boot, sidecars, diagnostics)

Examples:
  agentcage logs orchestrator
  agentcage logs orchestrator -f
  agentcage logs falco --lines 50
  agentcage logs cage <id>
  agentcage logs cage <id> --source agent
  agentcage logs cage <id> --source agent -f
  agentcage logs cage <id> --source infra
  agentcage logs assessment <id>
`)
}
