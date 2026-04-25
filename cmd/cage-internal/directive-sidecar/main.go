package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// DirectiveType matches cage.DirectiveType.
type DirectiveType string

const (
	DirectiveContinue   DirectiveType = "continue"
	DirectiveRedirect   DirectiveType = "redirect"
	DirectiveTerminate  DirectiveType = "terminate"
	DirectiveHoldResult DirectiveType = "hold_result"
)

type Directive struct {
	Sequence     int64                  `json:"sequence"`
	Instructions []DirectiveInstruction `json:"instructions"`
}

type DirectiveInstruction struct {
	Type    DirectiveType `json:"type"`
	Message string        `json:"message,omitempty"`
	HoldID  string        `json:"hold_id,omitempty"`
	Allowed bool          `json:"allowed,omitempty"`
	Reason  string        `json:"reason,omitempty"`
}

type AgentHoldRequest struct {
	HoldID  string         `json:"hold_id"`
	Message string         `json:"message"`
	Context map[string]any `json:"context,omitempty"`
}

type AgentHoldResponse struct {
	HoldID  string `json:"hold_id"`
	Allowed bool   `json:"allowed"`
	Message string `json:"message,omitempty"`
}

func main() {
	directivePath := flag.String("directive-file", "/var/run/agentcage/directives.json", "path to write directive file")
	holdSocket := flag.String("hold-socket", "/var/run/agentcage/hold.sock", "Unix socket for agent-initiated holds")
	logSocket := flag.String("log-socket", "/var/run/agentcage/logs.sock", "Unix socket for cage log collection")
	vsockPort := flag.Int("vsock-port", 52, "vsock port for receiving directives from host")
	holdVsockPort := flag.Int("hold-vsock-port", 53, "vsock port for forwarding holds to host")
	logVsockPort := flag.Int("log-vsock-port", 54, "vsock port for forwarding logs to host")
	flag.Parse()

	fmt.Printf("directive-sidecar: starting (directive_port=%d hold_port=%d log_port=%d)\n", *vsockPort, *holdVsockPort, *logVsockPort)

	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		serveDirectiveListener(uint32(*vsockPort), *directivePath)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		serveHoldSocket(*holdSocket, uint32(*holdVsockPort))
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		serveLogForwarder(*logSocket, uint32(*logVsockPort))
	}()

	wg.Wait()
}

// serveDirectiveListener accepts connections on an AF_VSOCK port and
// writes received directives to the directive file atomically.
func serveDirectiveListener(port uint32, directivePath string) {
	lis, err := listenVsock(port)
	if err != nil {
		fmt.Fprintf(os.Stderr, "directive-sidecar: listen vsock port %d: %v\n", port, err)
		os.Exit(1)
	}
	defer func() { _ = lis.Close() }()

	fmt.Printf("directive-sidecar: listening for directives on vsock port %d\n", port)

	for {
		conn, err := lis.Accept()
		if err != nil {
			fmt.Fprintf(os.Stderr, "directive-sidecar: accept directive conn: %v\n", err)
			continue
		}
		handleDirectiveConn(conn, directivePath)
	}
}

func handleDirectiveConn(conn net.Conn, directivePath string) {
	defer func() { _ = conn.Close() }()

	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 0, 64*1024), 64*1024)

	if !scanner.Scan() {
		fmt.Fprintf(os.Stderr, "directive-sidecar: no data from host: %v\n", scanner.Err())
		return
	}

	line := scanner.Bytes()
	var directive Directive
	if err := json.Unmarshal(line, &directive); err != nil {
		fmt.Fprintf(os.Stderr, "directive-sidecar: invalid directive JSON: %v\n", err)
		return
	}

	if err := writeDirectiveFile(directivePath, line); err != nil {
		fmt.Fprintf(os.Stderr, "directive-sidecar: writing directive file: %v\n", err)
		return
	}

	fmt.Printf("directive-sidecar: directive received (seq=%d instructions=%d)\n", directive.Sequence, len(directive.Instructions))

	// ACK: single byte tells the host the write landed on disk.
	_, _ = conn.Write([]byte{0x06}) // ACK
}

// writeDirectiveFile writes atomically: tmp file + rename.
func writeDirectiveFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp := filepath.Join(dir, ".directive.tmp")
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		return fmt.Errorf("writing tmp: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("renaming to %s: %w", path, err)
	}
	return nil
}

// serveHoldSocket listens on a Unix socket for agent hold requests,
// forwards them to the host over vsock, and relays responses back.
// The hold socket stays as Unix because the agent is local to the cage.
func serveHoldSocket(socketPath string, holdVsockPort uint32) {
	_ = os.Remove(socketPath)

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "directive-sidecar: listen hold socket %s: %v\n", socketPath, err)
		os.Exit(1)
	}
	defer func() { _ = listener.Close() }()

	fmt.Printf("directive-sidecar: hold socket ready at %s\n", socketPath)

	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Fprintf(os.Stderr, "directive-sidecar: accept hold conn: %v\n", err)
			continue
		}
		go handleHoldConn(conn, holdVsockPort)
	}
}

func handleHoldConn(conn net.Conn, holdVsockPort uint32) {
	defer func() { _ = conn.Close() }()

	_ = conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 0, 64*1024), 64*1024)

	if !scanner.Scan() {
		fmt.Fprintf(os.Stderr, "directive-sidecar: no hold request from agent: %v\n", scanner.Err())
		return
	}

	var req AgentHoldRequest
	if err := json.Unmarshal(scanner.Bytes(), &req); err != nil {
		fmt.Fprintf(os.Stderr, "directive-sidecar: invalid hold request JSON: %v\n", err)
		writeHoldError(conn, "invalid JSON")
		return
	}

	if req.HoldID == "" || req.Message == "" {
		writeHoldError(conn, "hold_id and message are required")
		return
	}

	fmt.Printf("directive-sidecar: agent hold request (hold_id=%s)\n", req.HoldID)

	// Forward to host over vsock port 53. CID 2 is the host.
	response, err := forwardHoldToHost(holdVsockPort, scanner.Bytes())
	if err != nil {
		fmt.Fprintf(os.Stderr, "directive-sidecar: forwarding hold to host: %v\n", err)
		writeHoldError(conn, "host unreachable")
		return
	}

	_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	response = append(response, '\n')
	if _, err := conn.Write(response); err != nil {
		fmt.Fprintf(os.Stderr, "directive-sidecar: writing hold response to agent: %v\n", err)
	}

	fmt.Printf("directive-sidecar: hold resolved (hold_id=%s)\n", req.HoldID)
}

// forwardHoldToHost connects to the host via AF_VSOCK and relays the
// hold request. Blocks until the operator resolves on the host side.
func forwardHoldToHost(port uint32, requestPayload []byte) ([]byte, error) {
	conn, err := dialVsock(vsockCIDHost, port)
	if err != nil {
		return nil, fmt.Errorf("dialing host vsock port %d: %w", port, err)
	}
	defer func() { _ = conn.Close() }()

	payload := append(requestPayload, '\n')
	if _, err := conn.Write(payload); err != nil {
		return nil, fmt.Errorf("writing hold request: %w", err)
	}

	// Block until host responds. The hold timeout is enforced host-side
	// (default 15m). This deadline is a safety net if the host-side
	// enforcer is broken; 30 minutes gives ample headroom.
	_ = conn.SetReadDeadline(time.Now().Add(30 * time.Minute))
	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 0, 64*1024), 64*1024)
	if !scanner.Scan() {
		if scanner.Err() != nil {
			return nil, fmt.Errorf("reading host response: %w", scanner.Err())
		}
		return nil, fmt.Errorf("host closed connection without response")
	}

	return scanner.Bytes(), nil
}

func writeHoldError(conn net.Conn, msg string) {
	resp := AgentHoldResponse{Allowed: false, Message: msg}
	data, _ := json.Marshal(resp)
	data = append(data, '\n')
	_, _ = conn.Write(data)
}

// serveLogForwarder collects log lines from in-cage processes via a
// local Unix socket and forwards them to the host over vsock port 54.
// Cage-init and sidecars write JSON log lines to the log socket.
// The host-side VsockCollector reads them for operator visibility.
func serveLogForwarder(socketPath string, logVsockPort uint32) {
	_ = os.Remove(socketPath)

	localLis, err := net.Listen("unix", socketPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "directive-sidecar: listen log socket %s: %v\n", socketPath, err)
		return
	}
	defer func() { _ = localLis.Close() }()

	fmt.Printf("directive-sidecar: log socket ready at %s, waiting for host on vsock port %d\n", socketPath, logVsockPort)

	// Listen on vsock port 54. The host connects when it starts
	// monitoring the cage. One connection at a time.
	vsockLis, err := listenVsock(logVsockPort)
	if err != nil {
		fmt.Fprintf(os.Stderr, "directive-sidecar: listen vsock log port %d: %v\n", logVsockPort, err)
		return
	}
	defer func() { _ = vsockLis.Close() }()

	// Buffer lines from local writers and forward to the current
	// host connection. A channel decouples local accept from host
	// connectivity so local writers never block on the host.
	lines := make(chan []byte, 256)

	// Accept local connections (sidecars, agent)
	go func() {
		for {
			conn, err := localLis.Accept()
			if err != nil {
				return
			}
			go collectLocal(conn, lines)
		}
	}()

	// Accept host connections and forward buffered lines
	for {
		hostConn, err := vsockLis.Accept()
		if err != nil {
			fmt.Fprintf(os.Stderr, "directive-sidecar: accept vsock log conn: %v\n", err)
			continue
		}
		fmt.Println("directive-sidecar: host log collector connected")
		forwardToHost(hostConn, lines)
		fmt.Println("directive-sidecar: host log collector disconnected")
	}
}

func collectLocal(conn net.Conn, out chan<- []byte) {
	defer func() { _ = conn.Close() }()
	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 0, 64*1024), 64*1024)
	for scanner.Scan() {
		line := make([]byte, len(scanner.Bytes()))
		copy(line, scanner.Bytes())
		select {
		case out <- line:
		default:
			// Drop oldest if buffer full. Better to lose a log line
			// than block an in-cage process.
		}
	}
}

func forwardToHost(conn net.Conn, lines <-chan []byte) {
	defer func() { _ = conn.Close() }()
	for {
		select {
		case line, ok := <-lines:
			if !ok {
				return
			}
			line = append(line, '\n')
			_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			if _, err := conn.Write(line); err != nil {
				return
			}
		case <-time.After(30 * time.Second):
			// Liveness probe: attempt a zero-byte write to detect
			// a disconnected host. If the connection is dead, the
			// write deadline fires and we exit cleanly.
			_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
			if _, err := conn.Write(nil); err != nil {
				return
			}
		}
	}
}
