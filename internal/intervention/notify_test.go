package intervention

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testRequest() Request {
	return Request{
		ID:           "int-001",
		Type:         TypeTripwireEscalation,
		Status:       StatusPending,
		Priority:     PriorityCritical,
		CageID:       "cage-abc",
		AssessmentID: "assess-xyz",
		Description:  "tripwire fired",
		Timeout:      5 * time.Minute,
		CreatedAt:    time.Now(),
	}
}

func TestWebhookNotifier_NotifyCreated(t *testing.T) {
	var received WebhookPayload
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		require.NoError(t, json.Unmarshal(body, &received))
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	notifier := NewWebhookNotifier([]string{srv.URL}, 5*time.Second, logr.Discard())
	err := notifier.NotifyCreated(context.Background(), testRequest())
	require.NoError(t, err)

	assert.Equal(t, "intervention.created", received.Event)
	assert.Equal(t, "int-001", received.Intervention.ID)
	assert.Equal(t, "cage-abc", received.Intervention.CageID)
}

func TestWebhookNotifier_NotifyResolved(t *testing.T) {
	var received WebhookPayload
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		require.NoError(t, json.Unmarshal(body, &received))
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	notifier := NewWebhookNotifier([]string{srv.URL}, 5*time.Second, logr.Discard())
	req := testRequest()
	req.Status = StatusResolved
	now := time.Now()
	req.ResolvedAt = &now

	err := notifier.NotifyResolved(context.Background(), req)
	require.NoError(t, err)

	assert.Equal(t, "intervention.resolved", received.Event)
	assert.Equal(t, "int-001", received.Intervention.ID)
}

func TestWebhookNotifier_MultipleEndpoints(t *testing.T) {
	var mu sync.Mutex
	var calls int

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls++
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	})

	srv1 := httptest.NewServer(handler)
	defer srv1.Close()
	srv2 := httptest.NewServer(handler)
	defer srv2.Close()

	notifier := NewWebhookNotifier([]string{srv1.URL, srv2.URL}, 5*time.Second, logr.Discard())
	err := notifier.NotifyCreated(context.Background(), testRequest())
	require.NoError(t, err)

	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, 2, calls)
}

func TestWebhookNotifier_EndpointFailure(t *testing.T) {
	failSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer failSrv.Close()

	var received WebhookPayload
	okSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		require.NoError(t, json.Unmarshal(body, &received))
		w.WriteHeader(http.StatusOK)
	}))
	defer okSrv.Close()

	notifier := NewWebhookNotifier([]string{failSrv.URL, okSrv.URL}, 5*time.Second, logr.Discard())

	err := notifier.NotifyCreated(context.Background(), testRequest())
	require.NoError(t, err)

	assert.Equal(t, "intervention.created", received.Event)
	assert.Equal(t, "int-001", received.Intervention.ID)
}

func TestNoopNotifier(t *testing.T) {
	n := &NoopNotifier{}
	ctx := context.Background()
	req := testRequest()

	assert.NoError(t, n.NotifyCreated(ctx, req))
	assert.NoError(t, n.NotifyResolved(ctx, req))
	assert.NoError(t, n.NotifyTimedOut(ctx, req))
}
