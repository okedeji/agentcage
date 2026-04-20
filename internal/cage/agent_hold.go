package cage

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/go-logr/logr"
)

// AgentHoldListener accepts hold requests from agents inside cage VMs
// over vsock. When an agent sends a hold request, the listener
// enqueues an intervention and blocks the vsock connection until the
// operator resolves it, then writes the response back.
type AgentHoldListener struct {
	enqueuer        InterventionEnqueuer
	interventionTTL time.Duration
	log             logr.Logger

	mu        sync.Mutex
	listeners map[string]net.Listener // vmID -> vsock listener
	pending   map[string]chan AgentHoldResponse // interventionID -> response channel
}

type AgentHoldListenerConfig struct {
	Enqueuer        InterventionEnqueuer
	InterventionTTL time.Duration
	Log             logr.Logger
}

func NewAgentHoldListener(cfg AgentHoldListenerConfig) *AgentHoldListener {
	return &AgentHoldListener{
		enqueuer:        cfg.Enqueuer,
		interventionTTL: cfg.InterventionTTL,
		log:             cfg.Log.WithValues("component", "agent-hold-listener"),
		listeners:       make(map[string]net.Listener),
		pending:         make(map[string]chan AgentHoldResponse),
	}
}

// StartForVM begins listening for agent hold requests from a specific
// VM's vsock UDS. Called after ProvisionVM succeeds.
func (l *AgentHoldListener) StartForVM(ctx context.Context, vmID, cageID, assessmentID, vsockPath string) {
	// The host-side vsock UDS is shared for all ports. Firecracker
	// routes by port after the CONNECT handshake. We listen on the
	// same UDS but handle port 53 connections.
	go l.listenLoop(ctx, vmID, cageID, assessmentID, vsockPath)
}

// StopForVM stops listening for hold requests from a VM and unblocks
// any pending holds with a block response.
func (l *AgentHoldListener) StopForVM(vmID string) {
	l.mu.Lock()
	lis, ok := l.listeners[vmID]
	if ok {
		delete(l.listeners, vmID)
	}
	l.mu.Unlock()

	if ok {
		_ = lis.Close()
	}
}

// ResolveHold sends a response to a blocked agent hold request.
// Called by the intervention service when an operator resolves an
// agent_hold intervention. The signature matches intervention.AgentHoldResolver.
func (l *AgentHoldListener) ResolveHold(interventionID string, allowed bool, message string) error {
	l.mu.Lock()
	ch, ok := l.pending[interventionID]
	if ok {
		delete(l.pending, interventionID)
	}
	l.mu.Unlock()

	if !ok {
		return fmt.Errorf("no pending agent hold for intervention %s", interventionID)
	}

	response := AgentHoldResponse{Allowed: allowed, Message: message}
	select {
	case ch <- response:
		return nil
	default:
		return fmt.Errorf("agent hold %s already resolved", interventionID)
	}
}

func (l *AgentHoldListener) listenLoop(ctx context.Context, vmID, cageID, assessmentID, vsockPath string) {
	// The Firecracker vsock UDS accepts connections from the host side.
	// For agent-initiated holds, the guest connects to the host (CID 2)
	// on port 53. On the host side, Firecracker delivers these as
	// connections on the UDS. We accept them and handle the hold protocol.
	//
	// In practice, the vsock UDS is a single socket. The host side needs
	// to accept connections that arrive when the guest dials out. We
	// listen on the UDS to accept guest-initiated connections.
	lis, err := net.Listen("unix", vsockPath+".hold")
	if err != nil {
		l.log.Error(err, "listening for agent holds", "vm_id", vmID, "path", vsockPath)
		return
	}

	l.mu.Lock()
	l.listeners[vmID] = lis
	l.mu.Unlock()

	l.log.Info("agent hold listener started", "vm_id", vmID, "cage_id", cageID)

	for {
		conn, err := lis.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			l.mu.Lock()
			_, active := l.listeners[vmID]
			l.mu.Unlock()
			if !active {
				return // StopForVM was called
			}
			l.log.Error(err, "accepting agent hold connection", "vm_id", vmID)
			continue
		}
		go l.handleHoldConn(ctx, conn, cageID, assessmentID)
	}
}

func (l *AgentHoldListener) handleHoldConn(ctx context.Context, conn net.Conn, cageID, assessmentID string) {
	defer func() { _ = conn.Close() }()

	_ = conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 0, 64*1024), 64*1024)

	if !scanner.Scan() {
		l.log.Error(scanner.Err(), "reading agent hold request", "cage_id", cageID)
		return
	}

	var req AgentHoldRequest
	if err := json.Unmarshal(scanner.Bytes(), &req); err != nil {
		l.log.Error(err, "invalid agent hold request JSON", "cage_id", cageID)
		l.writeResponse(conn, AgentHoldResponse{Allowed: false, Message: "invalid request"})
		return
	}

	if req.Message == "" {
		l.writeResponse(conn, AgentHoldResponse{Allowed: false, Message: "message is required"})
		return
	}

	description := fmt.Sprintf("agent hold: %s", req.Message)
	contextData, _ := json.Marshal(req)

	interventionID, err := l.enqueuer.Enqueue(
		ctx,
		InterventionAgentHold,
		InterventionPriorityHigh,
		cageID, assessmentID,
		description, contextData,
		l.interventionTTL,
	)
	if err != nil {
		l.log.Error(err, "enqueuing agent hold intervention", "cage_id", cageID, "hold_id", req.HoldID)
		l.writeResponse(conn, AgentHoldResponse{HoldID: req.HoldID, Allowed: false, Message: "failed to enqueue"})
		return
	}

	l.log.Info("agent hold enqueued",
		"cage_id", cageID,
		"hold_id", req.HoldID,
		"intervention_id", interventionID,
	)

	// Block until the operator resolves or the intervention times out.
	ch := make(chan AgentHoldResponse, 1)
	l.mu.Lock()
	l.pending[interventionID] = ch
	l.mu.Unlock()

	defer func() {
		l.mu.Lock()
		delete(l.pending, interventionID)
		l.mu.Unlock()
	}()

	// No read deadline while blocking. The intervention timeout
	// enforcer on the orchestrator side handles expiration.
	_ = conn.SetReadDeadline(time.Time{})
	_ = conn.SetWriteDeadline(time.Time{})

	select {
	case response := <-ch:
		response.HoldID = req.HoldID
		l.writeResponse(conn, response)
		l.log.Info("agent hold resolved", "cage_id", cageID, "hold_id", req.HoldID, "allowed", response.Allowed)
	case <-ctx.Done():
		l.writeResponse(conn, AgentHoldResponse{HoldID: req.HoldID, Allowed: false, Message: "cage shutting down"})
	}
}

func (l *AgentHoldListener) writeResponse(conn net.Conn, resp AgentHoldResponse) {
	data, _ := json.Marshal(resp)
	data = append(data, '\n')
	_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, _ = conn.Write(data)
}
