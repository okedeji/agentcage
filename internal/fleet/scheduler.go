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

// SimpleScheduler places cage workloads onto fleet hosts using
// first-available bin-packing. Suitable for single-host and small
// multi-host deployments. For larger fleets use NomadScheduler.
type SimpleScheduler struct {
	pool   *PoolManager
	mu     sync.Mutex
	allocs map[string]*allocation
	ipSeq  uint32
}

func NewSimpleScheduler(pool *PoolManager) *SimpleScheduler {
	return &SimpleScheduler{
		pool:   pool,
		allocs: make(map[string]*allocation),
	}
}

func (s *SimpleScheduler) Schedule(ctx context.Context, config cage.VMConfig) (*cage.VMHandle, error) {
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

	s.ipSeq++
	// 255 * 254 = 64770 unique IPs in 10.0.0.0/16 before wrap.
	if s.ipSeq > 255*254 {
		s.ipSeq = 1
	}
	octet3 := (s.ipSeq / 254) % 256
	octet4 := (s.ipSeq % 254) + 1
	return &cage.VMHandle{
		ID:        vmID,
		CageID:    config.CageID,
		IPAddress: fmt.Sprintf("10.0.%d.%d", octet3, octet4),
		StartedAt: time.Now(),
	}, nil
}

var ErrAllocationNotFound = fmt.Errorf("VM allocation not found")

func (s *SimpleScheduler) Deallocate(ctx context.Context, vmID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	alloc, ok := s.allocs[vmID]
	if !ok {
		return fmt.Errorf("deallocating VM %s: %w", vmID, ErrAllocationNotFound)
	}

	if err := s.pool.ReleaseCageSlot(alloc.hostID); err != nil {
		return fmt.Errorf("deallocating VM %s: releasing slot on host %s: %w", vmID, alloc.hostID, err)
	}

	delete(s.allocs, vmID)
	return nil
}

func (s *SimpleScheduler) Status(ctx context.Context, vmID string) (cage.VMStatus, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.allocs[vmID]; ok {
		return cage.VMStatusRunning, nil
	}
	return cage.VMStatusStopped, fmt.Errorf("VM %s: %w", vmID, ErrAllocationNotFound)
}
