package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/okedeji/agentcage/internal/findings"
)

func main() {
	socketPath := flag.String("socket", "/var/run/agentcage/findings.sock", "Unix socket path")
	vsockPort := flag.Int("vsock-port", 55, "vsock port for forwarding findings to host")
	assessmentID := flag.String("assessment-id", "", "assessment ID for finding attribution")
	cageID := flag.String("cage-id", "", "cage ID for finding attribution")
	flag.Parse()

	if *assessmentID == "" || *cageID == "" {
		fmt.Fprintln(os.Stderr, "error: -assessment-id and -cage-id are required")
		os.Exit(1)
	}

	hostConn, err := dialVsockRetry(uint32(*vsockPort))
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: connecting to host vsock port %d: %v\n", *vsockPort, err)
		os.Exit(1)
	}
	defer func() { _ = hostConn.Close() }()

	fmt.Printf("findings-sidecar: connected to host on vsock port %d\n", *vsockPort)

	_ = os.Remove(*socketPath)
	listener, err := net.Listen("unix", *socketPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: listening on %s: %v\n", *socketPath, err)
		os.Exit(1)
	}
	defer func() { _ = listener.Close() }()

	fmt.Printf("findings-sidecar: listening on %s\n", *socketPath)

	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Fprintf(os.Stderr, "findings-sidecar: accept: %v\n", err)
			continue
		}
		go handleConnection(conn, hostConn, *assessmentID, *cageID)
	}
}

func handleConnection(conn net.Conn, hostConn net.Conn, assessmentID, cageID string) {
	defer func() { _ = conn.Close() }()
	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	for scanner.Scan() {
		line := scanner.Bytes()

		var finding findings.Finding
		if err := json.Unmarshal(line, &finding); err != nil {
			fmt.Fprintf(os.Stderr, "findings-sidecar: invalid JSON from agent: %v\n", err)
			continue
		}

		const maxFieldBytes = 256 * 1024
		if len(finding.Evidence.Request) > maxFieldBytes {
			finding.Evidence.Request = finding.Evidence.Request[:maxFieldBytes]
		}
		if len(finding.Evidence.Response) > maxFieldBytes {
			finding.Evidence.Response = finding.Evidence.Response[:maxFieldBytes]
		}
		if len(finding.Evidence.Screenshot) > maxFieldBytes {
			finding.Evidence.Screenshot = finding.Evidence.Screenshot[:maxFieldBytes]
		}

		finding.CageID = cageID
		finding.AssessmentID = assessmentID
		now := time.Now()
		if finding.CreatedAt.IsZero() {
			finding.CreatedAt = now
		}
		if finding.UpdatedAt.IsZero() {
			finding.UpdatedAt = now
		}

		if err := findings.ValidateFinding(finding); err != nil {
			fmt.Fprintf(os.Stderr, "findings-sidecar: invalid finding %s: %v\n", finding.ID, err)
			_, _ = fmt.Fprintf(conn, "error: invalid finding %s: %v\n", finding.ID, err)
			continue
		}

		findings.SanitizeFinding(&finding, nil)

		msg := findings.Message{
			SchemaVersion: findings.CurrentSchemaVersion,
			Finding:       finding,
		}
		data, err := json.Marshal(msg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "findings-sidecar: marshaling finding %s: %v\n", finding.ID, err)
			continue
		}

		data = append(data, '\n')
		_ = hostConn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if _, err := hostConn.Write(data); err != nil {
			fmt.Fprintf(os.Stderr, "findings-sidecar: writing finding %s to host: %v\n", finding.ID, err)
			continue
		}

		fmt.Printf("findings-sidecar: finding forwarded (id=%s vuln_class=%s)\n", finding.ID, finding.VulnClass)
	}

	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "findings-sidecar: reading from agent: %v\n", err)
	}
}
