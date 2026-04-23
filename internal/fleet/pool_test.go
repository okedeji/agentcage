package fleet

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testHost(id string, pool HostPool, slotsTotal, slotsUsed int32) Host {
	return Host{
		ID:             id,
		Pool:           pool,
		State:          HostReady,
		CageSlotsTotal: slotsTotal,
		CageSlotsUsed:  slotsUsed,
		VCPUsTotal:     96,
		MemoryMBTotal:  196608,
	}
}

func TestPoolManager_AddAndGetHost(t *testing.T) {
	pm := NewPoolManager()
	_ = pm.AddHost(testHost("host-1", PoolActive, 48, 0))

	h, err := pm.GetHost("host-1")
	require.NoError(t, err)
	assert.Equal(t, "host-1", h.ID)
	assert.Equal(t, PoolActive, h.Pool)
	assert.Equal(t, int32(48), h.CageSlotsTotal)
}

func TestPoolManager_GetHost_NotFound(t *testing.T) {
	pm := NewPoolManager()

	_, err := pm.GetHost("nonexistent")
	assert.ErrorIs(t, err, ErrHostNotFound)
}

func TestPoolManager_AllocateCageSlot(t *testing.T) {
	pm := NewPoolManager()
	_ = pm.AddHost(testHost("host-1", PoolActive, 2, 0))

	require.NoError(t, pm.AllocateCageSlot("host-1"))

	h, err := pm.GetHost("host-1")
	require.NoError(t, err)
	assert.Equal(t, int32(1), h.CageSlotsUsed)
}

func TestPoolManager_AllocateCageSlot_AtCapacity(t *testing.T) {
	pm := NewPoolManager()
	_ = pm.AddHost(testHost("host-1", PoolActive, 2, 2))

	err := pm.AllocateCageSlot("host-1")
	assert.ErrorIs(t, err, ErrNoCapacity)
}

func TestPoolManager_AllocateCageSlot_NotFound(t *testing.T) {
	pm := NewPoolManager()

	err := pm.AllocateCageSlot("nonexistent")
	assert.ErrorIs(t, err, ErrHostNotFound)
}

func TestPoolManager_ReleaseCageSlot(t *testing.T) {
	pm := NewPoolManager()
	_ = pm.AddHost(testHost("host-1", PoolActive, 10, 5))

	require.NoError(t, pm.ReleaseCageSlot("host-1"))

	h, err := pm.GetHost("host-1")
	require.NoError(t, err)
	assert.Equal(t, int32(4), h.CageSlotsUsed)
}

func TestPoolManager_ReleaseCageSlot_AtZero(t *testing.T) {
	pm := NewPoolManager()
	_ = pm.AddHost(testHost("host-1", PoolActive, 10, 0))

	err := pm.ReleaseCageSlot("host-1")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "slot count already zero")
}

func TestPoolManager_GetAvailableHost_PrefersActive(t *testing.T) {
	pm := NewPoolManager()
	_ = pm.AddHost(testHost("warm-1", PoolWarm, 10, 0))
	_ = pm.AddHost(testHost("active-1", PoolActive, 10, 0))

	h, err := pm.GetAvailableHost()
	require.NoError(t, err)
	assert.Equal(t, "active-1", h.ID)
}

func TestPoolManager_GetAvailableHost_FallsBackToWarm(t *testing.T) {
	pm := NewPoolManager()
	_ = pm.AddHost(testHost("active-1", PoolActive, 10, 10))
	_ = pm.AddHost(testHost("warm-1", PoolWarm, 10, 0))

	h, err := pm.GetAvailableHost()
	require.NoError(t, err)
	assert.Equal(t, "warm-1", h.ID)
}

func TestPoolManager_GetAvailableHost_NoCapacity(t *testing.T) {
	pm := NewPoolManager()
	_ = pm.AddHost(testHost("host-1", PoolActive, 2, 2))
	_ = pm.AddHost(testHost("host-2", PoolDraining, 10, 0))

	_, err := pm.GetAvailableHost()
	assert.ErrorIs(t, err, ErrNoCapacity)
}

func TestPoolManager_GetAvailableHost_Empty(t *testing.T) {
	pm := NewPoolManager()

	_, err := pm.GetAvailableHost()
	assert.ErrorIs(t, err, ErrNoCapacity)
}

func TestPoolManager_MoveHost(t *testing.T) {
	pm := NewPoolManager()
	_ = pm.AddHost(testHost("host-1", PoolActive, 10, 0))

	require.NoError(t, pm.MoveHost("host-1", PoolDraining))

	h, err := pm.GetHost("host-1")
	require.NoError(t, err)
	assert.Equal(t, PoolDraining, h.Pool)
}

func TestPoolManager_MoveHost_NotFound(t *testing.T) {
	pm := NewPoolManager()

	err := pm.MoveHost("nonexistent", PoolDraining)
	assert.ErrorIs(t, err, ErrHostNotFound)
}

func TestPoolManager_RemoveHost(t *testing.T) {
	pm := NewPoolManager()
	_ = pm.AddHost(testHost("host-1", PoolActive, 10, 0))

	require.NoError(t, pm.RemoveHost("host-1"))

	_, err := pm.GetHost("host-1")
	assert.ErrorIs(t, err, ErrHostNotFound)
}

func TestPoolManager_RemoveHost_NotFound(t *testing.T) {
	pm := NewPoolManager()

	err := pm.RemoveHost("nonexistent")
	assert.ErrorIs(t, err, ErrHostNotFound)
}

func TestPoolManager_GetFleetStatus(t *testing.T) {
	pm := NewPoolManager()
	_ = pm.AddHost(testHost("a-1", PoolActive, 10, 3))
	_ = pm.AddHost(testHost("a-2", PoolActive, 10, 7))
	_ = pm.AddHost(testHost("w-1", PoolWarm, 10, 0))

	status := pm.GetFleetStatus()
	assert.Equal(t, int32(3), status.TotalHosts)
	assert.InDelta(t, 10.0/30.0, status.CapacityUtilizationRatio, 0.001)

	poolCounts := make(map[HostPool]int32)
	for _, ps := range status.Pools {
		poolCounts[ps.Pool] = ps.HostCount
	}
	assert.Equal(t, int32(2), poolCounts[PoolActive])
	assert.Equal(t, int32(1), poolCounts[PoolWarm])
}

func TestPoolManager_GetFleetStatus_Empty(t *testing.T) {
	pm := NewPoolManager()

	status := pm.GetFleetStatus()
	assert.Equal(t, int32(0), status.TotalHosts)
	assert.Equal(t, float64(0), status.CapacityUtilizationRatio)
}

func TestPoolManager_GetPoolStatus(t *testing.T) {
	pm := NewPoolManager()
	_ = pm.AddHost(testHost("a-1", PoolActive, 10, 3))
	_ = pm.AddHost(testHost("a-2", PoolActive, 10, 7))

	statuses := pm.GetPoolStatus()
	require.Len(t, statuses, 1)
	assert.Equal(t, PoolActive, statuses[0].Pool)
	assert.Equal(t, int32(2), statuses[0].HostCount)
	assert.Equal(t, int32(20), statuses[0].CageSlotsTotal)
	assert.Equal(t, int32(10), statuses[0].CageSlotsUsed)
}
