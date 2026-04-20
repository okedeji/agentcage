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
	vsockPort := flag.Int("vsock-port", 52, "vsock port for receiving directives from host")
	holdVsockPort := flag.Int("hold-vsock-port", 53, "vsock port for forwarding holds to host")
	flag.Parse()

	fmt.Printf("directive-sidecar: starting (directive_port=%d hold_port=%d)\n", *vsockPort, *holdVsockPort)

	var wg sync.WaitGroup

	// Goroutine 1: listen for directives from host on vsock port 52
	wg.Add(1)
	go func() {
		defer wg.Done()
		serveDirectiveListener(*vsockPort, *directivePath)
	}()

	// Goroutine 2: serve agent hold socket
	wg.Add(1)
	go func() {
		defer wg.Done()
		serveHoldSocket(*holdSocket, *holdVsockPort)
	}()

	wg.Wait()
}

// serveDirectiveListener accepts connections on a vsock port and writes
// received directives to the directive file atomically.
func serveDirectiveListener(port int, directivePath string) {
	// Inside a Firecracker guest, vsock is exposed as AF_VSOCK. The
	// guest listens on a port; the host connects via the UDS proxy.
	// We use a Unix socket as a stand-in that cage-init's iptables or
	// the kernel's AF_VSOCK bind provides. In production this is
	// AF_VSOCK; for portability we listen on a Unix socket that the
	// vsock-proxy maps to the AF_VSOCK port.
	sockPath := fmt.Sprintf("/var/run/agentcage/vsock-%d.sock", port)
	_ = os.Remove(sockPath)

	listener, err := net.Listen("unix", sockPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "directive-sidecar: listen vsock port %d: %v\n", port, err)
		os.Exit(1)
	}
	defer func() { _ = listener.Close() }()

	fmt.Printf("directive-sidecar: listening for directives on %s\n", sockPath)

	for {
		conn, err := listener.Accept()
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
func serveHoldSocket(socketPath string, holdVsockPort int) {
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

func handleHoldConn(conn net.Conn, holdVsockPort int) {
	defer func() { _ = conn.Close() }()

	// Read the agent's hold request (single JSON line)
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

	// Forward to host over vsock port 53
	response, err := forwardHoldToHost(holdVsockPort, scanner.Bytes())
	if err != nil {
		fmt.Fprintf(os.Stderr, "directive-sidecar: forwarding hold to host: %v\n", err)
		writeHoldError(conn, "host unreachable")
		return
	}

	// Relay host response back to the agent (unblocks the agent)
	_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	response = append(response, '\n')
	if _, err := conn.Write(response); err != nil {
		fmt.Fprintf(os.Stderr, "directive-sidecar: writing hold response to agent: %v\n", err)
	}

	fmt.Printf("directive-sidecar: hold resolved (hold_id=%s)\n", req.HoldID)
}

// forwardHoldToHost connects to the host via vsock port 53 and relays
// the hold request. The host will block until the operator resolves,
// then send back the response.
func forwardHoldToHost(port int, requestPayload []byte) ([]byte, error) {
	// Connect to host vsock. Inside the guest, CID 2 is the host.
	// We use a Unix socket mapped by the vsock proxy for portability.
	hostSock := fmt.Sprintf("/var/run/agentcage/vsock-%d.sock", port)

	conn, err := net.DialTimeout("unix", hostSock, 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("dialing host vsock port %d: %w", port, err)
	}
	defer func() { _ = conn.Close() }()

	// Send request
	payload := append(requestPayload, '\n')
	if _, err := conn.Write(payload); err != nil {
		return nil, fmt.Errorf("writing hold request: %w", err)
	}

	// Block until host responds. The operator may take minutes;
	// the hold timeout is enforced on the host side.
	_ = conn.SetReadDeadline(time.Now().Add(25 * time.Hour))
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
