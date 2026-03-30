package slo

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestTracker(now time.Time) *Tracker {
	targets := map[Indicator]float64{
		IndicatorCageStartup:         0.99,
		IndicatorGatewayAvailability: 0.999,
	}
	tr := NewTracker(targets, 24*time.Hour)
	tr.now = func() time.Time { return now }
	return tr
}

func TestTracker_RecordAndGetCurrent(t *testing.T) {
	now := time.Date(2026, 3, 28, 12, 0, 0, 0, time.UTC)
	tr := newTestTracker(now)

	tr.Record(IndicatorCageStartup, 3.2, true)
	tr.Record(IndicatorCageStartup, 6.1, false)

	m := tr.GetCurrent(IndicatorCageStartup)
	require.NotNil(t, m)
	assert.Equal(t, 6.1, m.Value)
	assert.False(t, m.Good)
}

func TestTracker_GetCurrent_UnknownIndicator(t *testing.T) {
	now := time.Date(2026, 3, 28, 12, 0, 0, 0, time.UTC)
	tr := newTestTracker(now)

	assert.Nil(t, tr.GetCurrent(IndicatorCageStartup))
}

func TestTracker_GetErrorBudget_AllGood(t *testing.T) {
	now := time.Date(2026, 3, 28, 12, 0, 0, 0, time.UTC)
	tr := newTestTracker(now)

	for i := range 100 {
		tr.now = func() time.Time { return now.Add(time.Duration(i) * time.Minute) }
		tr.Record(IndicatorCageStartup, 2.0, true)
	}
	tr.now = func() time.Time { return now.Add(100 * time.Minute) }

	b := tr.GetErrorBudget(IndicatorCageStartup)
	require.NotNil(t, b)
	assert.Equal(t, 0.99, b.BudgetTotal)
	assert.InDelta(t, 0.0, b.BudgetConsumed, 0.001)
	assert.InDelta(t, 0.99, b.BudgetRemaining, 0.001)
}

func TestTracker_GetErrorBudget_SomeBad(t *testing.T) {
	now := time.Date(2026, 3, 28, 12, 0, 0, 0, time.UTC)
	tr := newTestTracker(now)

	for i := range 90 {
		tr.now = func() time.Time { return now.Add(time.Duration(i) * time.Minute) }
		tr.Record(IndicatorCageStartup, 2.0, true)
	}
	for i := 90; i < 100; i++ {
		tr.now = func() time.Time { return now.Add(time.Duration(i) * time.Minute) }
		tr.Record(IndicatorCageStartup, 6.0, false)
	}
	tr.now = func() time.Time { return now.Add(100 * time.Minute) }

	b := tr.GetErrorBudget(IndicatorCageStartup)
	require.NotNil(t, b)
	assert.InDelta(t, 0.10, b.BudgetConsumed, 0.001)
	assert.InDelta(t, 0.89, b.BudgetRemaining, 0.001)
}

func TestTracker_GetErrorBudget_AllBad(t *testing.T) {
	now := time.Date(2026, 3, 28, 12, 0, 0, 0, time.UTC)
	tr := newTestTracker(now)

	for i := range 100 {
		tr.now = func() time.Time { return now.Add(time.Duration(i) * time.Minute) }
		tr.Record(IndicatorCageStartup, 10.0, false)
	}
	tr.now = func() time.Time { return now.Add(100 * time.Minute) }

	b := tr.GetErrorBudget(IndicatorCageStartup)
	require.NotNil(t, b)
	assert.InDelta(t, 1.0, b.BudgetConsumed, 0.001)
	assert.InDelta(t, 0.0, b.BudgetRemaining, 0.001)
}

func TestTracker_GetErrorBudget_BurnRate(t *testing.T) {
	now := time.Date(2026, 3, 28, 0, 0, 0, 0, time.UTC)
	tr := NewTracker(map[Indicator]float64{IndicatorCageStartup: 0.99}, 24*time.Hour)

	// Record over half the window: 12 hours elapsed out of 24 hour window
	for i := range 100 {
		tr.now = func() time.Time { return now.Add(time.Duration(i) * time.Minute) }
		good := i < 90
		tr.Record(IndicatorCageStartup, float64(i), good)
	}
	// Set "now" to 12 hours after the first measurement
	tr.now = func() time.Time { return now.Add(12 * time.Hour) }

	b := tr.GetErrorBudget(IndicatorCageStartup)
	require.NotNil(t, b)
	// consumed = 0.10, elapsed fraction = 12h/24h = 0.5, burn rate = 0.10/0.5 = 0.20
	assert.InDelta(t, 0.20, b.BurnRate, 0.01)
}

func TestTracker_GetErrorBudget_UnknownIndicator(t *testing.T) {
	tr := NewTracker(map[Indicator]float64{}, 24*time.Hour)
	assert.Nil(t, tr.GetErrorBudget(IndicatorCageStartup))
}

func TestTracker_GetErrorBudget_NoMeasurements(t *testing.T) {
	now := time.Date(2026, 3, 28, 12, 0, 0, 0, time.UTC)
	tr := newTestTracker(now)

	b := tr.GetErrorBudget(IndicatorCageStartup)
	require.NotNil(t, b)
	assert.Equal(t, 0.99, b.BudgetRemaining)
	assert.Equal(t, 0.0, b.BudgetConsumed)
	assert.Equal(t, 0.0, b.BurnRate)
}

func TestTracker_Prune(t *testing.T) {
	now := time.Date(2026, 3, 28, 12, 0, 0, 0, time.UTC)
	tr := newTestTracker(now)

	// Record an old measurement outside the window
	tr.now = func() time.Time { return now.Add(-48 * time.Hour) }
	tr.Record(IndicatorCageStartup, 1.0, true)

	// Record a recent measurement inside the window
	tr.now = func() time.Time { return now.Add(-1 * time.Hour) }
	tr.Record(IndicatorCageStartup, 2.0, true)

	tr.now = func() time.Time { return now }
	tr.Prune()

	m := tr.GetCurrent(IndicatorCageStartup)
	require.NotNil(t, m)
	assert.Equal(t, 2.0, m.Value)

	tr.mu.RLock()
	assert.Len(t, tr.measurements[IndicatorCageStartup], 1)
	tr.mu.RUnlock()
}

func TestTracker_GetAll(t *testing.T) {
	now := time.Date(2026, 3, 28, 12, 0, 0, 0, time.UTC)
	tr := newTestTracker(now)

	tr.Record(IndicatorCageStartup, 2.0, true)
	tr.Record(IndicatorGatewayAvailability, 1.0, true)

	budgets := tr.GetAll()
	assert.Len(t, budgets, 2)
}

func TestTracker_Record_UnknownIndicator_Ignored(t *testing.T) {
	now := time.Date(2026, 3, 28, 12, 0, 0, 0, time.UTC)
	tr := newTestTracker(now)

	tr.Record(IndicatorFleetWarmBuffer, 1.0, true)
	assert.Nil(t, tr.GetCurrent(IndicatorFleetWarmBuffer))
}
