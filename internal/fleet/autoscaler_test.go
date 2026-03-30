package fleet

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

type mockProvisioner struct {
	mu          sync.Mutex
	provisioned []*Host
	drained     []string
	nextHost    func() *Host
}

func (m *mockProvisioner) Provision(_ context.Context) (*Host, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	h := m.nextHost()
	m.provisioned = append(m.provisioned, h)
	return h, nil
}

func (m *mockProvisioner) Drain(_ context.Context, hostID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.drained = append(m.drained, hostID)
	return nil
}

func newTestAutoscaler(pool *PoolManager, demand *DemandLedger, prov *mockProvisioner, min, max int32) *Autoscaler {
	return NewAutoscaler(pool, demand, prov, AutoscalerConfig{
		PollInterval: 30 * time.Second,
		MinBuffer:    min,
		MaxBuffer:    max,
		DefaultCageResources: CageResources{
			VCPUs:    4,
			MemoryMB: 8192,
		},
	}, logr.Discard())
}

func hostGenerator() func() *Host {
	var mu sync.Mutex
	counter := 0
	return func() *Host {
		mu.Lock()
		defer mu.Unlock()
		counter++
		return &Host{
			ID:             fmt.Sprintf("host-%d", counter),
			State:          HostReady,
			CageSlotsTotal: 16,
			VCPUsTotal:     64,
			MemoryMBTotal:  131072,
		}
	}
}

func TestReconcile_WarmBelowMinimum(t *testing.T) {
	pool := NewPoolManager()
	demand := NewDemandLedger()
	prov := &mockProvisioner{nextHost: hostGenerator()}
	a := newTestAutoscaler(pool, demand, prov, 3, 5)

	a.reconcile(context.Background())

	prov.mu.Lock()
	defer prov.mu.Unlock()
	assert.Len(t, prov.provisioned, 3)

	warmHosts := pool.GetHostsByPool(PoolWarm)
	assert.Len(t, warmHosts, 3)
}

func TestReconcile_WarmAboveMaximumNoDemand(t *testing.T) {
	pool := NewPoolManager()
	demand := NewDemandLedger()
	prov := &mockProvisioner{nextHost: hostGenerator()}
	a := newTestAutoscaler(pool, demand, prov, 2, 5)

	for i := 0; i < 10; i++ {
		pool.AddHost(Host{
			ID:             fmt.Sprintf("warm-%d", i),
			Pool:           PoolWarm,
			State:          HostReady,
			CageSlotsTotal: 16,
			VCPUsTotal:     64,
			MemoryMBTotal:  131072,
			UpdatedAt:      time.Now().Add(time.Duration(i) * time.Minute),
		})
	}

	a.reconcile(context.Background())

	prov.mu.Lock()
	defer prov.mu.Unlock()
	assert.Len(t, prov.drained, 5)
}

func TestReconcile_WarmAboveMaximumWithDemand(t *testing.T) {
	pool := NewPoolManager()
	demand := NewDemandLedger()
	demand.AddDemand("assessment-1", 100)
	prov := &mockProvisioner{nextHost: hostGenerator()}
	a := newTestAutoscaler(pool, demand, prov, 2, 5)

	for i := 0; i < 10; i++ {
		pool.AddHost(Host{
			ID:             fmt.Sprintf("warm-%d", i),
			Pool:           PoolWarm,
			State:          HostReady,
			CageSlotsTotal: 16,
			VCPUsTotal:     64,
			MemoryMBTotal:  131072,
		})
	}

	a.reconcile(context.Background())

	prov.mu.Lock()
	defer prov.mu.Unlock()
	assert.Empty(t, prov.drained)
}

func TestReconcile_WarmWithinRange(t *testing.T) {
	pool := NewPoolManager()
	demand := NewDemandLedger()
	prov := &mockProvisioner{nextHost: hostGenerator()}
	a := newTestAutoscaler(pool, demand, prov, 2, 5)

	for i := 0; i < 3; i++ {
		pool.AddHost(Host{
			ID:             fmt.Sprintf("warm-%d", i),
			Pool:           PoolWarm,
			State:          HostReady,
			CageSlotsTotal: 16,
			VCPUsTotal:     64,
			MemoryMBTotal:  131072,
		})
	}

	a.reconcile(context.Background())

	prov.mu.Lock()
	defer prov.mu.Unlock()
	assert.Empty(t, prov.provisioned)
	assert.Empty(t, prov.drained)
}

func TestOnNewAssessment_SmallSurface(t *testing.T) {
	pool := NewPoolManager()
	demand := NewDemandLedger()
	prov := &mockProvisioner{nextHost: hostGenerator()}
	a := newTestAutoscaler(pool, demand, prov, 2, 5)

	a.OnNewAssessment("assessment-small", 30)

	assert.Equal(t, int32(150), demand.GetDemand("assessment-small"))

	prov.mu.Lock()
	provisioned := len(prov.provisioned)
	prov.mu.Unlock()
	assert.Greater(t, provisioned, 0)
}

func TestOnNewAssessment_LargeSurface(t *testing.T) {
	pool := NewPoolManager()
	demand := NewDemandLedger()
	prov := &mockProvisioner{nextHost: hostGenerator()}
	a := newTestAutoscaler(pool, demand, prov, 2, 5)

	a.OnNewAssessment("assessment-large", 300)

	assert.Equal(t, int32(1500), demand.GetDemand("assessment-large"))

	prov.mu.Lock()
	provisioned := len(prov.provisioned)
	prov.mu.Unlock()
	assert.Greater(t, provisioned, 0)
}

func TestRun_ContextCancellation(t *testing.T) {
	pool := NewPoolManager()
	demand := NewDemandLedger()
	prov := &mockProvisioner{nextHost: hostGenerator()}
	a := NewAutoscaler(pool, demand, prov, AutoscalerConfig{
		PollInterval: 10 * time.Millisecond,
		MinBuffer:    0,
		MaxBuffer:    10,
		DefaultCageResources: CageResources{
			VCPUs:    4,
			MemoryMB: 8192,
		},
	}, logr.Discard())

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- a.Run(ctx)
	}()

	cancel()

	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after context cancellation")
	}
}
