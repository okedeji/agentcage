package intervention

import (
	"context"
	"fmt"
	"sync"
)

type MemStore struct {
	mu    sync.Mutex
	items map[string]Request
}

func NewMemStore() *MemStore {
	return &MemStore{items: make(map[string]Request)}
}

func (m *MemStore) SaveIntervention(_ context.Context, req Request) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.items[req.ID]; exists {
		return fmt.Errorf("intervention %s already exists", req.ID)
	}
	m.items[req.ID] = req
	return nil
}

func (m *MemStore) UpdateIntervention(_ context.Context, req Request) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.items[req.ID]; !exists {
		return fmt.Errorf("intervention %s not found", req.ID)
	}
	m.items[req.ID] = req
	return nil
}

func (m *MemStore) GetIntervention(_ context.Context, id string) (*Request, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	req, exists := m.items[id]
	if !exists {
		return nil, fmt.Errorf("intervention %s not found", id)
	}
	return &req, nil
}

func (m *MemStore) ListInterventions(_ context.Context, filters ListFilters) ([]Request, string, error) {
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
