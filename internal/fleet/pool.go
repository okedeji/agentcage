package fleet

import (
	"errors"
	"fmt"
	"sync"
	"time"
)

var (
	ErrHostNotFound    = errors.New("host not found")
	ErrNoCapacity      = errors.New("no available host with capacity")
	ErrInvalidPoolMove = errors.New("invalid pool transition")
)

type PoolManager struct {
	mu    sync.RWMutex
	hosts map[string]*Host
}

func NewPoolManager() *PoolManager {
	return &PoolManager{
		hosts: make(map[string]*Host),
	}
}

func (pm *PoolManager) AddHost(host Host) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	host.UpdatedAt = time.Now()
	pm.hosts[host.ID] = &host
}

func (pm *PoolManager) RemoveHost(hostID string) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	if _, ok := pm.hosts[hostID]; !ok {
		return fmt.Errorf("removing host %s: %w", hostID, ErrHostNotFound)
	}
	delete(pm.hosts, hostID)
	return nil
}

func (pm *PoolManager) MoveHost(hostID string, toPool HostPool) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	h, ok := pm.hosts[hostID]
	if !ok {
		return fmt.Errorf("moving host %s to pool %s: %w", hostID, toPool, ErrHostNotFound)
	}
	h.Pool = toPool
	h.UpdatedAt = time.Now()
	return nil
}

func (pm *PoolManager) AllocateCageSlot(hostID string) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	h, ok := pm.hosts[hostID]
	if !ok {
		return fmt.Errorf("allocating cage slot on host %s: %w", hostID, ErrHostNotFound)
	}
	if h.CageSlotsUsed >= h.CageSlotsTotal {
		return fmt.Errorf("allocating cage slot on host %s: %w", hostID, ErrNoCapacity)
	}
	h.CageSlotsUsed++
	h.UpdatedAt = time.Now()
	return nil
}

func (pm *PoolManager) ReleaseCageSlot(hostID string) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	h, ok := pm.hosts[hostID]
	if !ok {
		return fmt.Errorf("releasing cage slot on host %s: %w", hostID, ErrHostNotFound)
	}
	if h.CageSlotsUsed <= 0 {
		return nil
	}
	h.CageSlotsUsed--
	h.UpdatedAt = time.Now()
	return nil
}

func (pm *PoolManager) GetAvailableHost() (*Host, error) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	// Active pool hosts are preferred over warm pool hosts
	// to avoid promoting warm hosts unnecessarily.
	var warmCandidate *Host
	for _, h := range pm.hosts {
		if h.CageSlotsUsed >= h.CageSlotsTotal {
			continue
		}
		if h.Pool == PoolActive {
			copy := *h
			return &copy, nil
		}
		if h.Pool == PoolWarm && warmCandidate == nil {
			warmCandidate = h
		}
	}
	if warmCandidate != nil {
		copy := *warmCandidate
		return &copy, nil
	}
	return nil, ErrNoCapacity
}

func (pm *PoolManager) GetHost(hostID string) (*Host, error) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	h, ok := pm.hosts[hostID]
	if !ok {
		return nil, fmt.Errorf("getting host %s: %w", hostID, ErrHostNotFound)
	}
	copy := *h
	return &copy, nil
}

func (pm *PoolManager) GetHostsByPool(pool HostPool) []Host {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	var result []Host
	for _, h := range pm.hosts {
		if h.Pool == pool {
			result = append(result, *h)
		}
	}
	return result
}

func (pm *PoolManager) GetPoolStatus() []PoolStatus {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	poolMap := make(map[HostPool]*PoolStatus)
	for _, h := range pm.hosts {
		ps, ok := poolMap[h.Pool]
		if !ok {
			ps = &PoolStatus{Pool: h.Pool}
			poolMap[h.Pool] = ps
		}
		ps.HostCount++
		ps.CageSlotsTotal += h.CageSlotsTotal
		ps.CageSlotsUsed += h.CageSlotsUsed
	}

	result := make([]PoolStatus, 0, len(poolMap))
	for _, ps := range poolMap {
		result = append(result, *ps)
	}
	return result
}

func (pm *PoolManager) GetFleetStatus() FleetStatus {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	var totalHosts int32
	var totalSlots int32
	var usedSlots int32
	poolMap := make(map[HostPool]*PoolStatus)

	for _, h := range pm.hosts {
		totalHosts++
		totalSlots += h.CageSlotsTotal
		usedSlots += h.CageSlotsUsed

		ps, ok := poolMap[h.Pool]
		if !ok {
			ps = &PoolStatus{Pool: h.Pool}
			poolMap[h.Pool] = ps
		}
		ps.HostCount++
		ps.CageSlotsTotal += h.CageSlotsTotal
		ps.CageSlotsUsed += h.CageSlotsUsed
	}

	pools := make([]PoolStatus, 0, len(poolMap))
	for _, ps := range poolMap {
		pools = append(pools, *ps)
	}

	var utilization float64
	if totalSlots > 0 {
		utilization = float64(usedSlots) / float64(totalSlots)
	}

	return FleetStatus{
		TotalHosts:               totalHosts,
		Pools:                    pools,
		CapacityUtilizationRatio: utilization,
	}
}
