package intervention

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type memStore struct {
	mu    sync.Mutex
	items map[string]Request
}

func newMemStore() *memStore {
	return &memStore{items: make(map[string]Request)}
}

func (m *memStore) SaveIntervention(_ context.Context, req Request) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.items[req.ID]; exists {
		return fmt.Errorf("intervention %s already exists", req.ID)
	}
	m.items[req.ID] = req
	return nil
}

func (m *memStore) UpdateIntervention(_ context.Context, req Request) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.items[req.ID]; !exists {
		return fmt.Errorf("intervention %s not found", req.ID)
	}
	m.items[req.ID] = req
	return nil
}

func (m *memStore) GetIntervention(_ context.Context, id string) (*Request, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	req, exists := m.items[id]
	if !exists {
		return nil, fmt.Errorf("intervention %s not found", id)
	}
	return &req, nil
}

func (m *memStore) ListInterventions(_ context.Context, filters ListFilters) ([]Request, string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	var result []Request
	for _, req := range m.items {
		if filters.StatusFilter != nil && req.Status != *filters.StatusFilter {
			continue
		}
		if filters.TypeFilter != nil && req.Type != *filters.TypeFilter {
			continue
		}
		if filters.AssessmentID != "" && req.AssessmentID != filters.AssessmentID {
			continue
		}
		result = append(result, req)
	}
	return result, "", nil
}

type recordingNotifier struct {
	mu      sync.Mutex
	created []Request
	resolved []Request
	timedOut []Request
}

func (n *recordingNotifier) NotifyCreated(_ context.Context, req Request) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.created = append(n.created, req)
	return nil
}

func (n *recordingNotifier) NotifyResolved(_ context.Context, req Request) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.resolved = append(n.resolved, req)
	return nil
}

func (n *recordingNotifier) NotifyTimedOut(_ context.Context, req Request) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.timedOut = append(n.timedOut, req)
	return nil
}

func (n *recordingNotifier) NotifyExpiring(_ context.Context, _ Request, _ time.Duration) error {
	return nil
}

func newTestQueue() (*Queue, *memStore, *recordingNotifier) {
	store := newMemStore()
	notifier := &recordingNotifier{}
	q := NewQueue(store, notifier, logr.Discard())
	return q, store, notifier
}

func TestEnqueue(t *testing.T) {
	q, store, _ := newTestQueue()
	ctx := context.Background()

	req, err := q.Enqueue(ctx, TypeTripwireEscalation, PriorityCritical, "cage-1", "assess-1", "tripwire fired", []byte(`{"detail":"test"}`), 5*time.Minute)
	require.NoError(t, err)

	assert.NotEmpty(t, req.ID)
	assert.Equal(t, TypeTripwireEscalation, req.Type)
	assert.Equal(t, StatusPending, req.Status)
	assert.Equal(t, PriorityCritical, req.Priority)
	assert.Equal(t, "cage-1", req.CageID)
	assert.Equal(t, "assess-1", req.AssessmentID)
	assert.Equal(t, "tripwire fired", req.Description)
	assert.False(t, req.CreatedAt.IsZero())

	stored, err := store.GetIntervention(ctx, req.ID)
	require.NoError(t, err)
	assert.Equal(t, req.ID, stored.ID)
}

func TestEnqueueNotifies(t *testing.T) {
	q, _, notifier := newTestQueue()
	ctx := context.Background()

	_, err := q.Enqueue(ctx, TypePayloadReview, PriorityHigh, "cage-2", "assess-2", "suspicious payload", nil, 10*time.Minute)
	require.NoError(t, err)

	notifier.mu.Lock()
	defer notifier.mu.Unlock()
	require.Len(t, notifier.created, 1)
	assert.Equal(t, "cage-2", notifier.created[0].CageID)
}

func TestGetPendingSorted(t *testing.T) {
	q, _, _ := newTestQueue()
	ctx := context.Background()

	_, err := q.Enqueue(ctx, TypePayloadReview, PriorityLow, "cage-low", "a-1", "low", nil, 10*time.Minute)
	require.NoError(t, err)

	_, err = q.Enqueue(ctx, TypeTripwireEscalation, PriorityCritical, "cage-crit", "a-1", "critical", nil, 10*time.Minute)
	require.NoError(t, err)

	_, err = q.Enqueue(ctx, TypeReportReview, PriorityMedium, "cage-med", "a-1", "medium", nil, 10*time.Minute)
	require.NoError(t, err)

	pending, err := q.GetPending(ctx)
	require.NoError(t, err)
	require.Len(t, pending, 3)

	assert.Equal(t, PriorityCritical, pending[0].Priority)
	assert.Equal(t, PriorityMedium, pending[1].Priority)
	assert.Equal(t, PriorityLow, pending[2].Priority)
}

func TestResolve(t *testing.T) {
	q, store, notifier := newTestQueue()
	ctx := context.Background()

	req, err := q.Enqueue(ctx, TypeTripwireEscalation, PriorityHigh, "cage-1", "a-1", "test", nil, 10*time.Minute)
	require.NoError(t, err)

	decision := Decision{
		InterventionID: req.ID,
		Action:         ActionResume,
		Rationale:      "false alarm",
		OperatorID:     "op-1",
		DecidedAt:      time.Now(),
	}

	err = q.Resolve(ctx, req.ID, decision)
	require.NoError(t, err)

	stored, err := store.GetIntervention(ctx, req.ID)
	require.NoError(t, err)
	assert.Equal(t, StatusResolved, stored.Status)
	assert.NotNil(t, stored.ResolvedAt)

	pending, err := q.GetPending(ctx)
	require.NoError(t, err)
	assert.Empty(t, pending)

	notifier.mu.Lock()
	defer notifier.mu.Unlock()
	require.Len(t, notifier.resolved, 1)
}

func TestResolveAlreadyResolved(t *testing.T) {
	q, _, _ := newTestQueue()
	ctx := context.Background()

	req, err := q.Enqueue(ctx, TypeTripwireEscalation, PriorityHigh, "cage-1", "a-1", "test", nil, 10*time.Minute)
	require.NoError(t, err)

	decision := Decision{
		InterventionID: req.ID,
		Action:         ActionResume,
		Rationale:      "ok",
		OperatorID:     "op-1",
		DecidedAt:      time.Now(),
	}

	err = q.Resolve(ctx, req.ID, decision)
	require.NoError(t, err)

	err = q.Resolve(ctx, req.ID, decision)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNotPending)
}

func TestTimeOut(t *testing.T) {
	q, store, notifier := newTestQueue()
	ctx := context.Background()

	req, err := q.Enqueue(ctx, TypePayloadReview, PriorityMedium, "cage-1", "a-1", "test", nil, 5*time.Minute)
	require.NoError(t, err)

	err = q.TimeOut(ctx, req.ID)
	require.NoError(t, err)

	stored, err := store.GetIntervention(ctx, req.ID)
	require.NoError(t, err)
	assert.Equal(t, StatusTimedOut, stored.Status)
	assert.NotNil(t, stored.ResolvedAt)

	pending, err := q.GetPending(ctx)
	require.NoError(t, err)
	assert.Empty(t, pending)

	notifier.mu.Lock()
	defer notifier.mu.Unlock()
	require.Len(t, notifier.timedOut, 1)
}

func TestGetExpired(t *testing.T) {
	q, _, _ := newTestQueue()
	ctx := context.Background()

	_, err := q.Enqueue(ctx, TypeTripwireEscalation, PriorityHigh, "cage-old", "a-1", "old", nil, 1*time.Millisecond)
	require.NoError(t, err)

	time.Sleep(5 * time.Millisecond)

	_, err = q.Enqueue(ctx, TypePayloadReview, PriorityMedium, "cage-new", "a-1", "fresh", nil, 1*time.Hour)
	require.NoError(t, err)

	expired := q.GetExpired(time.Now())
	require.Len(t, expired, 1)
	assert.Equal(t, "cage-old", expired[0].CageID)
}

func TestListWithFilters(t *testing.T) {
	q, _, _ := newTestQueue()
	ctx := context.Background()

	_, err := q.Enqueue(ctx, TypeTripwireEscalation, PriorityHigh, "cage-1", "a-1", "one", nil, 10*time.Minute)
	require.NoError(t, err)

	_, err = q.Enqueue(ctx, TypePayloadReview, PriorityMedium, "cage-2", "a-2", "two", nil, 10*time.Minute)
	require.NoError(t, err)

	t.Run("filter by type", func(t *testing.T) {
		typ := TypeTripwireEscalation
		items, err := q.List(ctx, ListFilters{TypeFilter: &typ})
		require.NoError(t, err)
		require.Len(t, items, 1)
		assert.Equal(t, TypeTripwireEscalation, items[0].Type)
	})

	t.Run("filter by status", func(t *testing.T) {
		status := StatusPending
		items, err := q.List(ctx, ListFilters{StatusFilter: &status})
		require.NoError(t, err)
		assert.Len(t, items, 2)
	})

	t.Run("filter by assessment", func(t *testing.T) {
		items, err := q.List(ctx, ListFilters{AssessmentID: "a-2"})
		require.NoError(t, err)
		require.Len(t, items, 1)
		assert.Equal(t, "a-2", items[0].AssessmentID)
	})
}
