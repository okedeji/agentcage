package fleet

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/okedeji/agentcage/internal/cage"
)

type Scheduler interface {
	Schedule(ctx context.Context, config cage.VMConfig) (*cage.VMHandle, error)
	Deallocate(ctx context.Context, vmID string) error
	Status(ctx context.Context, vmID string) (cage.VMStatus, error)
}

type allocation struct {
	vmID   string
	hostID string
	config cage.VMConfig
}

// NomadScheduler places cage workloads onto fleet hosts.
// The actual Nomad API integration requires a running Nomad cluster
// and is wired in Phase 13. This implementation provides the interface
// contract with in-memory state tracking for workflow testing.
type NomadScheduler struct {
	pool   *PoolManager
	mu     sync.Mutex
	allocs map[string]*allocation
}

func NewNomadScheduler(pool *PoolManager) *NomadScheduler {
	return &NomadScheduler{
		pool:   pool,
		allocs: make(map[string]*allocation),
	}
}

func (s *NomadScheduler) Schedule(ctx context.Context, config cage.VMConfig) (*cage.VMHandle, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	host, err := s.pool.GetAvailableHost()
	if err != nil {
		return nil, fmt.Errorf("scheduling cage %s: %w", config.CageID, err)
	}

	if err := s.pool.AllocateCageSlot(host.ID); err != nil {
		return nil, fmt.Errorf("scheduling cage %s: allocating slot on host %s: %w", config.CageID, host.ID, err)
	}

	vmID := uuid.New().String()
	s.allocs[vmID] = &allocation{
		vmID:   vmID,
		hostID: host.ID,
		config: config,
	}

	return &cage.VMHandle{
		ID:        vmID,
		CageID:    config.CageID,
		IPAddress: fmt.Sprintf("10.0.0.%d", len(s.allocs)+1),
		StartedAt: time.Now(),
	}, nil
}

func (s *NomadScheduler) Deallocate(ctx context.Context, vmID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	alloc, ok := s.allocs[vmID]
	if !ok {
		return fmt.Errorf("deallocating VM %s: %w", vmID, ErrHostNotFound)
	}

	if err := s.pool.ReleaseCageSlot(alloc.hostID); err != nil {
		return fmt.Errorf("deallocating VM %s: releasing slot on host %s: %w", vmID, alloc.hostID, err)
	}

	delete(s.allocs, vmID)
	return nil
}

func (s *NomadScheduler) Status(ctx context.Context, vmID string) (cage.VMStatus, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.allocs[vmID]; ok {
		return cage.VMStatusRunning, nil
	}
	return cage.VMStatusStopped, nil
}
