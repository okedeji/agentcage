package cage

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"time"

	"github.com/go-logr/logr"

	agentmetrics "github.com/okedeji/agentcage/internal/metrics"
)

// FalcoAlertReader connects to a Falco Unix socket and reads JSON alert lines.
// Each alert is parsed into an AlertEvent and sent to the returned channel.
// The reader stops when the context is cancelled.
type FalcoAlertReader struct {
	socketPath string
	log        logr.Logger
}

func NewFalcoAlertReader(socketPath string, log logr.Logger) *FalcoAlertReader {
	if socketPath == "" {
		log.Info("falco socket path not configured, alert reader disabled")
	}
	return &FalcoAlertReader{
		socketPath: socketPath,
		log:        log.WithValues("component", "falco-reader"),
	}
}

type falcoJSONAlert struct {
	Time     string            `json:"time"`
	Rule     string            `json:"rule"`
	Priority string            `json:"priority"`
	Output   string            `json:"output"`
	Fields   map[string]string `json:"output_fields"`
}

// reconnectMaxBackoff caps the per-cage Falco reconnect backoff.
// Falco rarely restarts mid-cage in practice; most failures are short
// blips. The cap is small enough to recover quickly without
// hot-spinning when Falco is down for an extended period.
const (
	reconnectInitialBackoff = 500 * time.Millisecond
	reconnectMaxBackoff     = 30 * time.Second
)

// Stream connects to the Falco socket and sends parsed alerts to the
// returned channel. On disconnect it reconnects with exponential
// backoff until the cage's context is cancelled. Losing alerts
// mid-cage would silently degrade the behavioral tripwire layer.
//
// Returns the channel immediately. The first connect happens inside
// the goroutine; an early connection failure is logged and retried,
// never surfaced to the caller, since the cage workflow has no
// useful action to take other than retry.
func (r *FalcoAlertReader) Stream(ctx context.Context, cageID string) (<-chan AlertEvent, error) {
	ch := make(chan AlertEvent, 16)

	go func() {
		defer close(ch)

		backoff := reconnectInitialBackoff
		for {
			if ctx.Err() != nil {
				return
			}

			conn, err := net.DialTimeout("unix", r.socketPath, 5*time.Second)
			if err != nil {
				if agentmetrics.FalcoConnectionFailures != nil {
					agentmetrics.FalcoConnectionFailures.Add(ctx, 1)
				}
				r.log.Info("falco connect failed; retrying",
					"cage_id", cageID, "backoff", backoff, "error", err.Error())
				if !sleepCtx(ctx, backoff) {
					return
				}
				if backoff < reconnectMaxBackoff {
					backoff *= 2
					if backoff > reconnectMaxBackoff {
						backoff = reconnectMaxBackoff
					}
				}
				continue
			}
			backoff = reconnectInitialBackoff

			r.readLoop(ctx, conn, cageID, ch)
			_ = conn.Close()
		}
	}()

	return ch, nil
}

// readLoop drains a single Falco connection until EOF, error, or ctx done.
// Returns to the caller so Stream can decide whether to reconnect.
func (r *FalcoAlertReader) readLoop(ctx context.Context, conn net.Conn, cageID string, ch chan<- AlertEvent) {
	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		if ctx.Err() != nil {
			return
		}

		var raw falcoJSONAlert
		if err := json.Unmarshal(scanner.Bytes(), &raw); err != nil {
			r.log.V(1).Info("ignoring malformed Falco alert", "error", err)
			continue
		}

		containerID, ok := raw.Fields["container.id"]
		if !ok || containerID != cageID {
			continue
		}

		select {
		case ch <- AlertEvent{
			RuleName: raw.Rule,
			Priority: raw.Priority,
			Output:   raw.Output,
			CageID:   cageID,
		}:
		case <-ctx.Done():
			return
		}
	}
	if err := scanner.Err(); err != nil {
		r.log.Info("falco connection lost; will reconnect",
			"cage_id", cageID, "error", err.Error())
	} else {
		r.log.Info("falco connection closed by peer; will reconnect", "cage_id", cageID)
	}
}

// sleepCtx sleeps for d unless ctx is cancelled first. Returns false if
// ctx was cancelled.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-ctx.Done():
		return false
	}
}
