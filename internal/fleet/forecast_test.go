package fleet

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockForecastSource struct {
	forecast *Forecast
	err      error
}

func (m *mockForecastSource) GetForecast(_ context.Context) (*Forecast, error) {
	return m.forecast, m.err
}

type mockSignalSource struct {
	signals []WebhookSignal
	err     error
	acked   []WebhookSignal
}

func (m *mockSignalSource) GetPendingSignals(_ context.Context) ([]WebhookSignal, error) {
	return m.signals, m.err
}

func (m *mockSignalSource) AcknowledgeSignal(_ context.Context, signal WebhookSignal) error {
	m.acked = append(m.acked, signal)
	return nil
}

func newForecastTestAutoscaler(prov HostProvisioner) *Autoscaler {
	pool := NewPoolManager()
	demand := NewDemandLedger()
	cfg := AutoscalerConfig{
		PollInterval:         time.Minute,
		MinBuffer:            2,
		MaxBuffer:            10,
		DefaultCageResources: CageResources{VCPUs: 4, MemoryMB: 8192},
	}
	return NewAutoscaler(pool, demand, prov, cfg, logr.Discard())
}

func newForecastTestProvisioner() *forecastTestProvisioner {
	return &forecastTestProvisioner{}
}

type forecastTestProvisioner struct {
	provisioned int
}

func (p *forecastTestProvisioner) Provision(_ context.Context) (*Host, error) {
	p.provisioned++
	return &Host{
		ID:             fmt.Sprintf("host-%d", p.provisioned),
		State:          HostReady,
		VCPUsTotal:     64,
		MemoryMBTotal:  131072,
		CageSlotsTotal: 16,
	}, nil
}

func (p *forecastTestProvisioner) Drain(_ context.Context, _ string) error {
	return nil
}

func TestForecastIntegration_HighDemand_Provisions(t *testing.T) {
	prov := newForecastTestProvisioner()
	autoscaler := newForecastTestAutoscaler(prov)

	now := time.Now()
	fc := &Forecast{
		GeneratedAt: now,
		Predictions: []ForecastPoint{
			{Time: now.Add(10 * time.Minute), P50: 20, P80: 40, P95: 60},
		},
	}

	fi := NewForecastIntegration(autoscaler, &mockForecastSource{forecast: fc}, &mockSignalSource{}, time.Minute, logr.Discard())
	fi.applyForecast(context.Background())

	assert.Greater(t, prov.provisioned, 0)
}

func TestForecastIntegration_LowDemand_NoProvisioning(t *testing.T) {
	prov := newForecastTestProvisioner()
	autoscaler := newForecastTestAutoscaler(prov)

	for range 5 {
		host, _ := prov.Provision(context.Background())
		host.Pool = PoolWarm
		host.CageSlotsTotal = 16
		autoscaler.pool.AddHost(*host)
	}
	prov.provisioned = 0

	now := time.Now()
	fc := &Forecast{
		GeneratedAt: now,
		Predictions: []ForecastPoint{
			{Time: now.Add(10 * time.Minute), P50: 2, P80: 5, P95: 10},
		},
	}

	fi := NewForecastIntegration(autoscaler, &mockForecastSource{forecast: fc}, &mockSignalSource{}, time.Minute, logr.Discard())
	fi.applyForecast(context.Background())

	assert.Equal(t, 0, prov.provisioned)
}

func TestForecastIntegration_WebhookSignal_AddsDemand(t *testing.T) {
	prov := newForecastTestProvisioner()
	autoscaler := newForecastTestAutoscaler(prov)

	signals := &mockSignalSource{
		signals: []WebhookSignal{
			{CustomerID: "cust-1", AssessmentSize: "large", ScheduledAt: time.Now().Add(time.Hour)},
		},
	}

	fi := NewForecastIntegration(autoscaler, &mockForecastSource{forecast: &Forecast{}}, signals, time.Minute, logr.Discard())
	fi.applySignals(context.Background())

	assert.Equal(t, int32(1500), autoscaler.demand.CurrentDemand())
	require.Len(t, signals.acked, 1)
	assert.Equal(t, "cust-1", signals.acked[0].CustomerID)
}

func TestForecastIntegration_ForecastError_GracefulDegradation(t *testing.T) {
	prov := newForecastTestProvisioner()
	autoscaler := newForecastTestAutoscaler(prov)

	fi := NewForecastIntegration(
		autoscaler,
		&mockForecastSource{err: fmt.Errorf("forecast service unavailable")},
		&mockSignalSource{},
		time.Minute,
		logr.Discard(),
	)
	fi.applyForecast(context.Background())

	assert.Equal(t, 0, prov.provisioned)
}

func TestForecastIntegration_ContextCancellation_StopsLoop(t *testing.T) {
	prov := newForecastTestProvisioner()
	autoscaler := newForecastTestAutoscaler(prov)

	fi := NewForecastIntegration(
		autoscaler,
		&mockForecastSource{forecast: &Forecast{}},
		&mockSignalSource{},
		10*time.Millisecond,
		logr.Discard(),
	)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := fi.Run(ctx)
	assert.NoError(t, err)
}

func TestNearestPrediction(t *testing.T) {
	now := time.Now()
	predictions := []ForecastPoint{
		{Time: now.Add(5 * time.Minute), P80: 10},
		{Time: now.Add(10 * time.Minute), P80: 20},
		{Time: now.Add(20 * time.Minute), P80: 30},
	}

	target := now.Add(11 * time.Minute)
	p := nearestPrediction(predictions, target)
	require.NotNil(t, p)
	assert.Equal(t, int32(20), p.P80)
}

func TestNearestPrediction_Empty(t *testing.T) {
	assert.Nil(t, nearestPrediction(nil, time.Now()))
}

func TestEstimateSignalDemand(t *testing.T) {
	tests := []struct {
		size string
		want int32
	}{
		{"small", 150},
		{"medium", 500},
		{"large", 1500},
		{"unknown", 500},
	}
	for _, tt := range tests {
		t.Run(tt.size, func(t *testing.T) {
			assert.Equal(t, tt.want, estimateSignalDemand(tt.size))
		})
	}
}
