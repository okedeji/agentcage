package intervention

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
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

type NoopNotifier struct{}

func (n *NoopNotifier) NotifyCreated(_ context.Context, _ Request) error  { return nil }
func (n *NoopNotifier) NotifyResolved(_ context.Context, _ Request) error { return nil }
func (n *NoopNotifier) NotifyTimedOut(_ context.Context, _ Request) error { return nil }
