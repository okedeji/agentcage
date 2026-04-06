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
	h.Pool = PoolProvisioning
	h.State = HostInitializing
	m.provisioned = append(m.provisioned, h)
	return h, nil
}

func (m *mockProvisioner) Drain(_ context.Context, hostID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.drained = append(m.drained, hostID)
	return nil
}

func (m *mockProvisioner) Terminate(_ context.Context, hostID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.drained = append(m.drained, "terminated:"+hostID)
	return nil
}

func (m *mockProvisioner) CheckReady(_ context.Context, _ string) (bool, error) {
	return true, nil
}

func newTestAutoscaler(pool *PoolManager, demand *DemandLedger, prov *mockProvisioner, min, max int32) *Autoscaler {
	return NewAutoscaler(pool, demand, prov, nil, AutoscalerConfig{
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

	// First reconcile provisions hosts into PoolProvisioning
	a.reconcile(context.Background())

	prov.mu.Lock()
	assert.Len(t, prov.provisioned, 3)
	prov.mu.Unlock()

	// Second reconcile promotes them to PoolWarm (CheckReady returns true)
	a.reconcile(context.Background())

	warmHosts := pool.GetHostsByPool(PoolWarm)
	assert.Len(t, warmHosts, 3)
}

func TestReconcile_WarmAboveTargetNoDemand(t *testing.T) {
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

	// No demand → target = MinBuffer(2). 10 warm - 2 target = 8 drained.
	a.reconcile(context.Background())

	prov.mu.Lock()
	defer prov.mu.Unlock()
	assert.Len(t, prov.drained, 8)
}

func TestReconcile_WarmAboveTargetWithDemand(t *testing.T) {
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

	// demand=100, DefaultCageResources=4vCPU/8192MB, typicalHost=64vCPU →
	// slotsPerHost=16, hostsNeeded=ceil(100/16)=7. target=max(2,7)=7.
	// 10 warm - 7 target = 3 drained.
	a.reconcile(context.Background())

	prov.mu.Lock()
	defer prov.mu.Unlock()
	assert.Len(t, prov.drained, 3)
}

func TestReconcile_WarmAtTarget(t *testing.T) {
	pool := NewPoolManager()
	demand := NewDemandLedger()
	prov := &mockProvisioner{nextHost: hostGenerator()}
	a := newTestAutoscaler(pool, demand, prov, 3, 5)

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

	// 3 warm == MinBuffer(3), no demand → target=3. No drain, no provision.
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
	a := NewAutoscaler(pool, demand, prov, nil, AutoscalerConfig{
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
