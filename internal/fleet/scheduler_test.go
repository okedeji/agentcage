package fleet

import (
	"context"
	"testing"

	"github.com/okedeji/agentcage/internal/cage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestScheduler(hosts ...Host) *NomadScheduler {
	pm := NewPoolManager()
	for _, h := range hosts {
		_ = pm.AddHost(h)
	}
	return NewNomadScheduler(pm)
}

func TestNomadScheduler_Schedule(t *testing.T) {
	s := newTestScheduler(testHost("host-1", PoolActive, 10, 0))
	ctx := context.Background()

	handle, err := s.Schedule(ctx, cage.VMConfig{CageID: "cage-1", VCPUs: 2, MemoryMB: 4096})
	require.NoError(t, err)
	assert.NotEmpty(t, handle.ID)
	assert.Equal(t, "cage-1", handle.CageID)
	assert.NotEmpty(t, handle.IPAddress)

	h, _ := s.pool.GetHost("host-1")
	assert.Equal(t, int32(1), h.CageSlotsUsed)
}

func TestNomadScheduler_Schedule_NoCapacity(t *testing.T) {
	s := newTestScheduler(testHost("host-1", PoolActive, 1, 1))
	ctx := context.Background()

	_, err := s.Schedule(ctx, cage.VMConfig{CageID: "cage-1"})
	assert.ErrorIs(t, err, ErrNoCapacity)
}

func TestNomadScheduler_Schedule_EmptyFleet(t *testing.T) {
	s := newTestScheduler()
	ctx := context.Background()

	_, err := s.Schedule(ctx, cage.VMConfig{CageID: "cage-1"})
	assert.ErrorIs(t, err, ErrNoCapacity)
}

func TestNomadScheduler_Deallocate(t *testing.T) {
	s := newTestScheduler(testHost("host-1", PoolActive, 10, 0))
	ctx := context.Background()

	handle, err := s.Schedule(ctx, cage.VMConfig{CageID: "cage-1"})
	require.NoError(t, err)

	require.NoError(t, s.Deallocate(ctx, handle.ID))

	h, _ := s.pool.GetHost("host-1")
	assert.Equal(t, int32(0), h.CageSlotsUsed)
}

func TestNomadScheduler_Deallocate_Unknown(t *testing.T) {
	s := newTestScheduler()
	ctx := context.Background()

	err := s.Deallocate(ctx, "nonexistent")
	assert.ErrorIs(t, err, ErrAllocationNotFound)
}

func TestNomadScheduler_Status_Running(t *testing.T) {
	s := newTestScheduler(testHost("host-1", PoolActive, 10, 0))
	ctx := context.Background()

	handle, err := s.Schedule(ctx, cage.VMConfig{CageID: "cage-1"})
	require.NoError(t, err)

	status, err := s.Status(ctx, handle.ID)
	require.NoError(t, err)
	assert.Equal(t, cage.VMStatusRunning, status)
}

func TestNomadScheduler_Status_Unknown(t *testing.T) {
	s := newTestScheduler()
	ctx := context.Background()

	status, err := s.Status(ctx, "nonexistent")
	assert.ErrorIs(t, err, ErrAllocationNotFound)
	assert.Equal(t, cage.VMStatusStopped, status)
}
