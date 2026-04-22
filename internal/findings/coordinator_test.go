package findings

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockStore struct {
	mu       sync.Mutex
	findings map[string]Finding
	saveErr  error
}

func newMockStore() *mockStore {
	return &mockStore{findings: make(map[string]Finding)}
}

func (m *mockStore) SaveFinding(_ context.Context, f Finding) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.saveErr != nil {
		return m.saveErr
	}
	m.findings[f.ID] = f
	return nil
}

func (m *mockStore) FindingExists(_ context.Context, id string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.findings[id]
	return ok, nil
}

func (m *mockStore) GetByID(_ context.Context, id string) (Finding, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if f, ok := m.findings[id]; ok {
		return f, nil
	}
	return Finding{}, ErrFindingNotFound
}

func (m *mockStore) GetByAssessment(_ context.Context, assessmentID string, status Status) ([]Finding, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var result []Finding
	for _, f := range m.findings {
		if f.AssessmentID == assessmentID && f.Status == status {
			result = append(result, f)
		}
	}
	return result, nil
}

func (m *mockStore) CountByAssessment(_ context.Context, assessmentID string) (StatusCounts, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var counts StatusCounts
	for _, f := range m.findings {
		if f.AssessmentID != assessmentID {
			continue
		}
		switch f.Status {
		case StatusCandidate:
			counts.Candidate++
		case StatusValidated:
			counts.Validated++
		case StatusRejected:
			counts.Rejected++
		}
	}
	return counts, nil
}

func (m *mockStore) ListFindings(_ context.Context, filters ListFilters) ([]Finding, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var result []Finding
	for _, f := range m.findings {
		if filters.AssessmentID != "" && f.AssessmentID != filters.AssessmentID {
			continue
		}
		if filters.StatusFilter != nil && f.Status != *filters.StatusFilter {
			continue
		}
		if filters.SeverityFilter != nil && f.Severity != *filters.SeverityFilter {
			continue
		}
		result = append(result, f)
	}
	return result, nil
}

func (m *mockStore) DeleteFinding(_ context.Context, findingID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.findings[findingID]; !ok {
		return ErrFindingNotFound
	}
	delete(m.findings, findingID)
	return nil
}

func (m *mockStore) DeleteByAssessment(_ context.Context, assessmentID string) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var count int64
	for id, f := range m.findings {
		if f.AssessmentID == assessmentID {
			delete(m.findings, id)
			count++
		}
	}
	return count, nil
}

func (m *mockStore) UpdateStatus(_ context.Context, findingID string, status Status) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if f, ok := m.findings[findingID]; ok {
		f.Status = status
		m.findings[findingID] = f
	}
	return nil
}

func (m *mockStore) get(id string) (Finding, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	f, ok := m.findings[id]
	return f, ok
}

func newTestFinding() Finding {
	return Finding{
		ID:           "f-001",
		AssessmentID: "a-001",
		CageID:       "c-001",
		Status:       StatusCandidate,
		Severity:     SeverityHigh,
		Title:        "SQL Injection in /api/users",
		VulnClass:    "sqli",
		Endpoint:     "https://target.example.com/api/users",
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}
}

func TestCoordinator_ValidFinding(t *testing.T) {
	store := newMockStore()
	bloom := NewBloomFilter(1024, 3)
	coord := NewCoordinator(store, bloom, nil, logr.Discard())

	msg := Message{SchemaVersion: CurrentSchemaVersion, Finding: newTestFinding()}
	err := coord.HandleMessage(context.Background(), msg)
	require.NoError(t, err)

	saved, ok := store.get("f-001")
	assert.True(t, ok)
	assert.Equal(t, "f-001", saved.ID)
}

func TestCoordinator_InvalidFinding_Dropped(t *testing.T) {
	store := newMockStore()
	bloom := NewBloomFilter(1024, 3)
	coord := NewCoordinator(store, bloom, nil, logr.Discard())

	f := newTestFinding()
	f.ID = ""
	msg := Message{SchemaVersion: CurrentSchemaVersion, Finding: f}

	err := coord.HandleMessage(context.Background(), msg)
	require.NoError(t, err)

	_, ok := store.get("")
	assert.False(t, ok)
}

func TestCoordinator_DuplicateBloomHitAndPostgresHit(t *testing.T) {
	store := newMockStore()
	bloom := NewBloomFilter(1024, 3)
	coord := NewCoordinator(store, bloom, nil, logr.Discard())

	msg := Message{SchemaVersion: CurrentSchemaVersion, Finding: newTestFinding()}
	require.NoError(t, coord.HandleMessage(context.Background(), msg))

	err := coord.HandleMessage(context.Background(), msg)
	require.NoError(t, err)

	store.mu.Lock()
	assert.Len(t, store.findings, 1)
	store.mu.Unlock()
}

func TestCoordinator_DuplicateBloomMissPostgresHit(t *testing.T) {
	store := newMockStore()
	bloom := NewBloomFilter(1024, 3)
	coord := NewCoordinator(store, bloom, nil, logr.Discard())

	f := newTestFinding()
	store.mu.Lock()
	store.findings[f.ID] = f
	store.mu.Unlock()

	msg := Message{SchemaVersion: CurrentSchemaVersion, Finding: f}
	err := coord.HandleMessage(context.Background(), msg)
	require.NoError(t, err)

	store.mu.Lock()
	assert.Len(t, store.findings, 1)
	store.mu.Unlock()
}

func TestCoordinator_StoreError_ReturnsError(t *testing.T) {
	store := newMockStore()
	store.saveErr = errors.New("connection refused")
	bloom := NewBloomFilter(1024, 3)
	coord := NewCoordinator(store, bloom, nil, logr.Discard())

	msg := Message{SchemaVersion: CurrentSchemaVersion, Finding: newTestFinding()}
	err := coord.HandleMessage(context.Background(), msg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "saving finding")
}

func TestCoordinator_FindingSanitized(t *testing.T) {
	store := newMockStore()
	bloom := NewBloomFilter(1024, 3)
	coord := NewCoordinator(store, bloom, nil, logr.Discard())

	f := newTestFinding()
	f.Evidence.Request = make([]byte, maxEvidenceRequestSize+100)
	msg := Message{SchemaVersion: CurrentSchemaVersion, Finding: f}

	require.NoError(t, coord.HandleMessage(context.Background(), msg))

	saved, ok := store.get("f-001")
	require.True(t, ok)
	assert.Len(t, saved.Evidence.Request, maxEvidenceRequestSize)
}

func TestCoordinator_BloomUpdatedAfterSave(t *testing.T) {
	store := newMockStore()
	bloom := NewBloomFilter(1024, 3)
	coord := NewCoordinator(store, bloom, nil, logr.Discard())

	msg := Message{SchemaVersion: CurrentSchemaVersion, Finding: newTestFinding()}
	require.NoError(t, coord.HandleMessage(context.Background(), msg))

	assert.True(t, bloom.MayContain("a-001:f-001"))
}

func TestCoordinator_CrossAssessmentBloomIsolation(t *testing.T) {
	bloom := NewBloomFilter(1024, 3)

	bloom.Add("a-001:f-001")

	assert.True(t, bloom.MayContain("a-001:f-001"))
	assert.False(t, bloom.MayContain("a-002:f-001"),
		"bloom key scoped to assessment A should not match assessment B")
}

func TestCoordinator_EndpointRequired(t *testing.T) {
	store := newMockStore()
	bloom := NewBloomFilter(1024, 3)
	coord := NewCoordinator(store, bloom, nil, logr.Discard())

	f := newTestFinding()
	f.Endpoint = ""
	msg := Message{SchemaVersion: CurrentSchemaVersion, Finding: f}

	err := coord.HandleMessage(context.Background(), msg)
	require.NoError(t, err)

	_, ok := store.get(f.ID)
	assert.False(t, ok, "finding without endpoint should be dropped by validation")
}
