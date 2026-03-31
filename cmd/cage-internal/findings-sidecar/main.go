package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"

	"github.com/go-logr/logr"

	"github.com/okedeji/agentcage/internal/findings"
	proxylog "github.com/okedeji/agentcage/internal/log"
)

func main() {
	socketPath := flag.String("socket", "/var/run/agentcage/findings.sock", "Unix socket path")
	natsURL := flag.String("nats", "", "NATS server URL")
	assessmentID := flag.String("assessment-id", "", "assessment ID for NATS subject")
	cageID := flag.String("cage-id", "", "cage ID for finding attribution")
	flag.Parse()

	if *natsURL == "" || *assessmentID == "" || *cageID == "" {
		fmt.Fprintln(os.Stderr, "error: -nats, -assessment-id, and -cage-id are required")
		os.Exit(1)
	}

	logger, err := proxylog.New()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: creating logger: %v\n", err)
		os.Exit(1)
	}
	logger = logger.WithValues("component", "findings-sidecar", "cage_id", *cageID, "assessment_id", *assessmentID)

	bus, err := findings.NewNATSBus(*natsURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: connecting to NATS: %v\n", err)
		os.Exit(1)
	}
	defer bus.Close()

	_ = os.Remove(*socketPath) // best-effort cleanup of stale socket
	listener, err := net.Listen("unix", *socketPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: listening on %s: %v\n", *socketPath, err)
		os.Exit(1)
	}
	defer func() { _ = listener.Close() }()

	logger.Info("findings sidecar started", "socket", *socketPath)

	for {
		conn, err := listener.Accept()
		if err != nil {
			logger.Error(err, "accepting connection")
			continue
		}
		go handleConnection(conn, bus, *assessmentID, *cageID, logger)
	}
}

func handleConnection(conn net.Conn, bus findings.Bus, assessmentID, cageID string, logger logr.Logger) {
	defer func() { _ = conn.Close() }()
	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	for scanner.Scan() {
		line := scanner.Bytes()

		var finding findings.Finding
		if err := json.Unmarshal(line, &finding); err != nil {
			logger.Error(err, "invalid JSON from agent")
			continue
		}

		finding.CageID = cageID
		finding.AssessmentID = assessmentID

		if err := findings.ValidateFinding(finding); err != nil {
			logger.Error(err, "invalid finding from agent", "finding_id", finding.ID)
			continue
		}

		findings.SanitizeFinding(&finding)

		msg := findings.Message{
			SchemaVersion: findings.CurrentSchemaVersion,
			Finding:       finding,
		}
		if err := bus.Publish(context.Background(), assessmentID, msg); err != nil {
			logger.Error(err, "publishing finding to NATS", "finding_id", finding.ID)
			continue
		}

		logger.Info("finding forwarded", "finding_id", finding.ID, "vuln_class", finding.VulnClass)
	}

	if err := scanner.Err(); err != nil {
		logger.Error(err, "reading from agent connection")
	}
}
