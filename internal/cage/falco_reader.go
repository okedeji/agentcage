package cage

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"os"
	"time"

	"github.com/go-logr/logr"

	agentmetrics "github.com/okedeji/agentcage/internal/metrics"
)

// FalcoAlertReader tails a Falco JSON alert file and sends parsed
// alerts to consumers. Falco writes one JSON object per line via its
// file_output channel.
type FalcoAlertReader struct {
	alertFile string
	log       logr.Logger
}

func NewFalcoAlertReader(alertFile string, log logr.Logger) *FalcoAlertReader {
	if alertFile == "" {
		log.Info("falco alert file not configured, alert reader disabled")
	}
	return &FalcoAlertReader{
		alertFile: alertFile,
		log:       log.WithValues("component", "falco-reader"),
	}
}

type falcoJSONAlert struct {
	Time     string            `json:"time"`
	Rule     string            `json:"rule"`
	Priority string            `json:"priority"`
	Output   string            `json:"output"`
	Fields   map[string]string `json:"output_fields"`
}

const (
	tailPollInterval = 250 * time.Millisecond
	tailOpenRetry    = 2 * time.Second
)

// Stream tails the Falco alert file and sends parsed alerts to the
// returned channel. If the file doesn't exist yet, it retries until
// the context is cancelled. Losing alerts mid-cage would silently
// degrade the behavioral tripwire layer.
func (r *FalcoAlertReader) Stream(ctx context.Context, cageID string) (<-chan AlertEvent, error) {
	ch := make(chan AlertEvent, 16)

	go func() {
		defer close(ch)

		for {
			if ctx.Err() != nil {
				return
			}

			f, err := os.Open(r.alertFile)
			if err != nil {
				if agentmetrics.FalcoConnectionFailures != nil {
					agentmetrics.FalcoConnectionFailures.Add(ctx, 1)
				}
				r.log.V(1).Info("falco alert file not ready; retrying",
					"cage_id", cageID, "error", err.Error())
				if !sleepCtx(ctx, tailOpenRetry) {
					return
				}
				continue
			}

			// Seek to end so we only see new alerts from this point.
			_, _ = f.Seek(0, io.SeekEnd)
			r.tailLoop(ctx, f, cageID, ch)
			_ = f.Close()
		}
	}()

	return ch, nil
}

// tailLoop reads new lines appended to the file until ctx is done or
// the file is removed/truncated.
func (r *FalcoAlertReader) tailLoop(ctx context.Context, f *os.File, cageID string, ch chan<- AlertEvent) {
	reader := bufio.NewReader(f)

	for {
		if ctx.Err() != nil {
			return
		}

		line, err := reader.ReadBytes('\n')
		if err != nil {
			// EOF — poll for new data.
			if !sleepCtx(ctx, tailPollInterval) {
				return
			}
			continue
		}

		var raw falcoJSONAlert
		if err := json.Unmarshal(line, &raw); err != nil {
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
