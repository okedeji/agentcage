package runtime

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/okedeji/agentcage/internal/mcpgateway"
)

// controlReexecBackoff is how long the supervisor waits before re-exec'ing the
// activation bridge after its stream drops. Short, because a drop during a real
// run is usually the gateway going away as the run ends (the next loop sees the
// cancelled context and exits) or a transient exec hiccup the gateway recovers
// from by re-triggering. Long enough not to spin on a gateway that is gone.
const controlReexecBackoff = 500 * time.Millisecond

// activation is one in-progress on-demand boot. Concurrent callers for the same
// node wait on done and read err, so a node boots once however many edges hit it
// at once.
type activation struct {
	done chan struct{}
	err  error
}

// start launches the activation supervisor for a USES tree, the goroutine that
// holds the gateway's control stream open and boots sub-agents on demand. A
// single-container run has no gateway and nothing to activate, so it starts
// nothing. The caller owns ctx; releaseAll cancels it before teardown.
func (w *workingSet) start(ctx context.Context) {
	if w.plan == nil {
		return
	}
	ctx, cancel := context.WithCancel(ctx)
	w.mu.Lock()
	w.cancel = cancel
	w.mu.Unlock()
	go w.runControl(ctx)
}

// runControl keeps the activation stream into the gateway open for the run's
// life, re-exec'ing the bridge if it drops since the gateway re-triggers any
// activation the drop interrupted. It returns when ctx is cancelled, the run's
// shutdown path.
func (w *workingSet) runControl(ctx context.Context) {
	gateway := w.plan.MCPGateway.RunID
	for ctx.Err() == nil {
		_ = w.streamControl(ctx, gateway)
		select {
		case <-ctx.Done():
			return
		case <-time.After(controlReexecBackoff):
		}
	}
}

// streamControl runs one connection of the activation stream: it exec's the
// mcp-control bridge into the gateway container and speaks the activation
// protocol over its stdio. It returns when the stream ends, so runControl can
// re-establish it. Activations run concurrently so a slow boot does not stall
// the next request; writes back to the bridge are serialized by encMu.
func (w *workingSet) streamControl(ctx context.Context, gateway string) error {
	cmd := w.sess.provisioner.Nerdctl(ctx, "exec", "-i", gateway, gatewayBinaryPath, "mcp-control")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		return err
	}
	defer func() { _ = cmd.Wait() }()

	enc := json.NewEncoder(stdin)
	var encMu sync.Mutex
	dec := json.NewDecoder(stdout)
	for {
		var m mcpgateway.ControlMessage
		if err := dec.Decode(&m); err != nil {
			return err
		}
		if m.Type != mcpgateway.MsgActivate {
			continue
		}
		go w.handleActivate(ctx, m.Edge, enc, &encMu)
	}
}

// handleActivate boots the sub-agent an edge routes to and reports the verdict
// back over the stream. A boot error answers ok false, so the gateway fails the
// held call closed rather than forwarding to a cage that is not listening.
func (w *workingSet) handleActivate(ctx context.Context, edge string, enc *json.Encoder, encMu *sync.Mutex) {
	node, ok := w.plan.EdgeNodes[edge]
	var err error
	if !ok {
		err = fmt.Errorf("activate: unknown edge %s", edge)
	} else {
		err = w.activate(ctx, node)
	}
	encMu.Lock()
	_ = enc.Encode(mcpgateway.ControlMessage{Type: mcpgateway.MsgActivated, Edge: edge, OK: err == nil})
	encMu.Unlock()
}

// activate boots the node's cage unless it is already up, collapsing concurrent
// first-calls to one boot. It returns once the cage is live and reachable. The
// boot runs under the supervisor's context, not a short deadline, so a slow
// first build completes and serves the retry even after the gateway's own wait
// has failed the first call closed.
func (w *workingSet) activate(ctx context.Context, node string) error {
	w.mu.Lock()
	if w.closing {
		w.mu.Unlock()
		return fmt.Errorf("activate %s: run is shutting down", node)
	}
	if w.live[node] {
		w.mu.Unlock()
		return nil
	}
	if a, ok := w.inflight[node]; ok {
		w.mu.Unlock()
		<-a.done
		return a.err
	}
	a := &activation{done: make(chan struct{})}
	w.inflight[node] = a
	pa, planned := w.specByNode[node]
	w.mu.Unlock()

	var err error
	if !planned {
		err = fmt.Errorf("activate %s: no planned agent", node)
	} else {
		err = w.bootCage(ctx, pa)
	}

	w.mu.Lock()
	a.err = err
	delete(w.inflight, node)
	if err == nil {
		w.live[node] = true
	}
	w.mu.Unlock()
	close(a.done)
	return err
}

// bootCage builds the sub-agent's image if it is not cached and starts its
// container on its already-created network. Its removal is pushed onto the
// teardown the same way the skeleton's agents are, so a released run reaps an
// activated cage too.
func (w *workingSet) bootCage(ctx context.Context, pa plannedAgent) error {
	if err := buildAgentImage(ctx, w.sess, pa.Node, pa.Spec.ImageRef, w.noCache, w.stderr); err != nil {
		return fmt.Errorf("activating %s: %w", pa.Node.Key, err)
	}
	if err := startDetached(ctx, w.sess.provisioner, pa.Spec); err != nil {
		return fmt.Errorf("activating %s: %w", pa.Node.Key, err)
	}
	name := pa.Spec.RunID
	w.push(func() error { return removeContainer(w.sess.provisioner, name) })
	return nil
}
