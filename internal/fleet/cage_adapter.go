package fleet

import (
	"github.com/okedeji/agentcage/internal/cage"
)

// CagePoolAdapter wraps a *PoolManager so it satisfies cage.FleetPool.
// Lives here rather than in cage/ because cage importing fleet would
// create an import cycle (fleet already imports cage for scheduler).
type CagePoolAdapter struct {
	pool *PoolManager
}

// NewCagePoolAdapter wraps a PoolManager so it satisfies cage.FleetPool.
func NewCagePoolAdapter(pool *PoolManager) *CagePoolAdapter {
	return &CagePoolAdapter{pool: pool}
}

func (a *CagePoolAdapter) GetAvailableHost() (*cage.FleetHost, error) {
	h, err := a.pool.GetAvailableHost()
	if err != nil {
		return nil, err
	}
	return &cage.FleetHost{ID: h.ID, Pool: int(h.Pool)}, nil
}

func (a *CagePoolAdapter) AllocateCageSlot(hostID string) error {
	return a.pool.AllocateCageSlot(hostID)
}

func (a *CagePoolAdapter) ReleaseCageSlot(hostID string) error {
	return a.pool.ReleaseCageSlot(hostID)
}

func (a *CagePoolAdapter) MoveHost(hostID string, toPool int) error {
	return a.pool.MoveHost(hostID, HostPool(toPool))
}
