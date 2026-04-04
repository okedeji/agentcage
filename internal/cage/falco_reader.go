package cage

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"time"

	"github.com/go-logr/logr"
)

// FalcoAlertReader connects to a Falco Unix socket and reads JSON alert lines.
// Each alert is parsed into an AlertEvent and sent to the returned channel.
// The reader stops when the context is cancelled.
type FalcoAlertReader struct {
	socketPath string
	log        logr.Logger
}

func NewFalcoAlertReader(socketPath string, log logr.Logger) *FalcoAlertReader {
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

// Stream connects to the Falco socket and sends parsed alerts to the channel.
// Blocks until ctx is cancelled or the connection fails. Safe to call from
// a goroutine inside MonitorCage.
func (r *FalcoAlertReader) Stream(ctx context.Context, cageID string) (<-chan AlertEvent, error) {
	conn, err := net.DialTimeout("unix", r.socketPath, 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("connecting to Falco socket %s: %w", r.socketPath, err)
	}

	ch := make(chan AlertEvent, 16)

	go func() {
		defer func() {
			_ = conn.Close()
			close(ch)
		}()

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

			// Filter alerts for this cage only
			if containerID, ok := raw.Fields["container.id"]; ok && containerID != cageID {
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
	}()

	return ch, nil
}
