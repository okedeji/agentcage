package fleet

import (
	"context"
	"errors"
	"testing"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestServer_GetFleetStatus(t *testing.T) {
	pool := NewPoolManager()
	pool.AddHost(Host{
		ID:             "h-1",
		Pool:           PoolActive,
		State:          HostReady,
		CageSlotsTotal: 16,
		CageSlotsUsed:  4,
	})
	pool.AddHost(Host{
		ID:             "h-2",
		Pool:           PoolWarm,
		State:          HostReady,
		CageSlotsTotal: 16,
		CageSlotsUsed:  0,
	})

	srv := NewServer(pool, NewDemandLedger(), logr.Discard())
	status, err := srv.GetFleetStatus(context.Background())
	require.NoError(t, err)

	assert.Equal(t, int32(2), status.TotalHosts)
	assert.Len(t, status.Pools, 2)
}

func TestServer_DrainHost(t *testing.T) {
	pool := NewPoolManager()
	pool.AddHost(Host{
		ID:             "h-1",
		Pool:           PoolActive,
		State:          HostReady,
		CageSlotsTotal: 16,
	})

	srv := NewServer(pool, NewDemandLedger(), logr.Discard())
	err := srv.DrainHost(context.Background(), "h-1", "maintenance")
	require.NoError(t, err)

	host, err := pool.GetHost("h-1")
	require.NoError(t, err)
	assert.Equal(t, PoolDraining, host.Pool)
}

func TestServer_DrainHost_Unknown(t *testing.T) {
	pool := NewPoolManager()
	srv := NewServer(pool, NewDemandLedger(), logr.Discard())

	err := srv.DrainHost(context.Background(), "nonexistent", "test")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrHostNotFound))
}

func TestServer_GetCapacity(t *testing.T) {
	pool := NewPoolManager()
	pool.AddHost(Host{
		ID:             "h-1",
		Pool:           PoolActive,
		State:          HostReady,
		CageSlotsTotal: 16,
		CageSlotsUsed:  6,
	})
	pool.AddHost(Host{
		ID:             "h-2",
		Pool:           PoolWarm,
		State:          HostReady,
		CageSlotsTotal: 16,
		CageSlotsUsed:  0,
	})
	pool.AddHost(Host{
		ID:             "h-3",
		Pool:           PoolDraining,
		State:          HostDraining,
		CageSlotsTotal: 16,
		CageSlotsUsed:  2,
	})

	srv := NewServer(pool, NewDemandLedger(), logr.Discard())
	statuses, available, err := srv.GetCapacity(context.Background())
	require.NoError(t, err)

	assert.Len(t, statuses, 3)
	// Active: 16-6=10, Warm: 16-0=16, Draining excluded => 26
	assert.Equal(t, int32(26), available)
}
