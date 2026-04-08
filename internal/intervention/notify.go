package intervention

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/go-logr/logr"
)

type Notifier interface {
	NotifyCreated(ctx context.Context, req Request) error
	NotifyResolved(ctx context.Context, req Request) error
	NotifyTimedOut(ctx context.Context, req Request) error
}

type WebhookPayload struct {
	Event        string  `json:"event"`
	Intervention Request `json:"intervention"`
}

type WebhookNotifier struct {
	endpoints  []string
	headers    map[string]string
	httpClient *http.Client
	logger     logr.Logger
}

func NewWebhookNotifier(endpoints []string, timeout time.Duration, logger logr.Logger) *WebhookNotifier {
	return &WebhookNotifier{
		endpoints: endpoints,
		httpClient: &http.Client{
			Timeout: timeout,
		},
		logger: logger,
	}
}

func (w *WebhookNotifier) SetHeaders(headers map[string]string) {
	w.headers = headers
}

func (w *WebhookNotifier) NotifyCreated(ctx context.Context, req Request) error {
	return w.dispatch(ctx, "intervention.created", req)
}

func (w *WebhookNotifier) NotifyResolved(ctx context.Context, req Request) error {
	return w.dispatch(ctx, "intervention.resolved", req)
}

func (w *WebhookNotifier) NotifyTimedOut(ctx context.Context, req Request) error {
	return w.dispatch(ctx, "intervention.timed_out", req)
}

func (w *WebhookNotifier) dispatch(ctx context.Context, event string, req Request) error {
	payload := WebhookPayload{
		Event:        event,
		Intervention: req,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshaling webhook payload for event %s: %w", event, err)
	}

	for _, endpoint := range w.endpoints {
		w.sendToEndpoint(ctx, endpoint, body, event)
	}

	return nil
}

func (w *WebhookNotifier) sendToEndpoint(ctx context.Context, endpoint string, body []byte, event string) {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		w.logger.Error(err, "building webhook request", "endpoint", endpoint, "event", event)
		return
	}
	httpReq.Header.Set("Content-Type", "application/json")
	for k, v := range w.headers {
		httpReq.Header.Set(k, v)
	}

	resp, err := w.httpClient.Do(httpReq)
	if err != nil {
		w.logger.Error(err, "sending webhook notification", "endpoint", endpoint, "event", event)
		return
	}
	_ = resp.Body.Close() // best-effort cleanup, nothing actionable if it fails

	if resp.StatusCode >= 400 {
		w.logger.Error(
			fmt.Errorf("webhook returned HTTP %d", resp.StatusCode),
			"webhook endpoint returned error",
			"endpoint", endpoint,
			"event", event,
			"status_code", resp.StatusCode,
		)
	}
}

// LogNotifier prints intervention events to the terminal via structured logging
// and a human-readable line to stderr.
type LogNotifier struct {
	log logr.Logger
}

func NewLogNotifier(log logr.Logger) *LogNotifier {
	return &LogNotifier{log: log.WithValues("component", "intervention-notifier")}
}

func (n *LogNotifier) NotifyCreated(_ context.Context, req Request) error {
	n.log.Info("INTERVENTION CREATED, action required",
		"intervention_id", req.ID,
		"type", req.Type,
		"priority", req.Priority,
		"cage_id", req.CageID,
		"assessment_id", req.AssessmentID,
		"description", req.Description,
		"timeout", req.Timeout,
	)
	fmt.Fprintf(os.Stderr,
		"\n  *** INTERVENTION [%s] %s: %s (cage=%s, timeout=%s)\n      Resolve: agentcage resolve --id %s --action <resume|kill|allow|block>\n\n",
		req.Priority, req.Type, req.Description, req.CageID, req.Timeout, req.ID,
	)
	return nil
}

func (n *LogNotifier) NotifyResolved(_ context.Context, req Request) error {
	n.log.Info("intervention resolved",
		"intervention_id", req.ID,
		"cage_id", req.CageID,
	)
	return nil
}

func (n *LogNotifier) NotifyTimedOut(_ context.Context, req Request) error {
	n.log.Info("INTERVENTION TIMED OUT, cage will be killed",
		"intervention_id", req.ID,
		"cage_id", req.CageID,
		"assessment_id", req.AssessmentID,
	)
	fmt.Fprintf(os.Stderr,
		"\n  *** INTERVENTION TIMED OUT [%s] cage=%s, cage will be killed\n\n",
		req.ID, req.CageID,
	)
	return nil
}

// MultiNotifier fans out notifications to all configured notifiers.
// Errors from individual notifiers are logged but do not block others.
type MultiNotifier struct {
	notifiers []Notifier
	log       logr.Logger
}

func NewMultiNotifier(log logr.Logger, notifiers ...Notifier) *MultiNotifier {
	return &MultiNotifier{notifiers: notifiers, log: log}
}

func (m *MultiNotifier) NotifyCreated(ctx context.Context, req Request) error {
	for _, n := range m.notifiers {
		if err := n.NotifyCreated(ctx, req); err != nil {
			m.log.Error(err, "notifier failed on created event", "intervention_id", req.ID)
		}
	}
	return nil
}

func (m *MultiNotifier) NotifyResolved(ctx context.Context, req Request) error {
	for _, n := range m.notifiers {
		if err := n.NotifyResolved(ctx, req); err != nil {
			m.log.Error(err, "notifier failed on resolved event", "intervention_id", req.ID)
		}
	}
	return nil
}

func (m *MultiNotifier) NotifyTimedOut(ctx context.Context, req Request) error {
	for _, n := range m.notifiers {
		if err := n.NotifyTimedOut(ctx, req); err != nil {
			m.log.Error(err, "notifier failed on timed_out event", "intervention_id", req.ID)
		}
	}
	return nil
}

type NoopNotifier struct{}

func (n *NoopNotifier) NotifyCreated(_ context.Context, _ Request) error  { return nil }
func (n *NoopNotifier) NotifyResolved(_ context.Context, _ Request) error { return nil }
func (n *NoopNotifier) NotifyTimedOut(_ context.Context, _ Request) error { return nil }
