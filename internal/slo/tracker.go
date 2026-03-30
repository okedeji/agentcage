package slo

import (
	"sync"
	"time"
)

func DefaultTargets() map[Indicator]float64 {
	return map[Indicator]float64{
		IndicatorCageStartup:          0.99,
		IndicatorTeardownCompleteness: 1.0,
		IndicatorEgressEnforcement:    1.0,
		IndicatorPayloadFirewall:      0.999,
		IndicatorInterventionResponse: 0.90,
		IndicatorInterventionTimeout:  0.95,
		IndicatorReportReview:         0.90,
		IndicatorAuditLogDelivery:     1.0,
		IndicatorGatewayAvailability:  0.999,
		IndicatorFindingsBusDelivery:  1.0,
		IndicatorFleetWarmBuffer:      0.99,
	}
}

type Tracker struct {
	mu           sync.RWMutex
	measurements map[Indicator][]Measurement
	targets      map[Indicator]float64
	windowSize   time.Duration
	now          func() time.Time
}

func NewTracker(targets map[Indicator]float64, windowSize time.Duration) *Tracker {
	return &Tracker{
		measurements: make(map[Indicator][]Measurement),
		targets:      targets,
		windowSize:   windowSize,
		now:          time.Now,
	}
}

func (t *Tracker) Record(indicator Indicator, value float64, good bool) {
	target, ok := t.targets[indicator]
	if !ok {
		return
	}

	m := Measurement{
		Indicator: indicator,
		Value:     value,
		Target:    target,
		Good:      good,
		Timestamp: t.now(),
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	t.measurements[indicator] = append(t.measurements[indicator], m)
}

func (t *Tracker) GetCurrent(indicator Indicator) *Measurement {
	t.mu.RLock()
	defer t.mu.RUnlock()

	ms := t.measurements[indicator]
	if len(ms) == 0 {
		return nil
	}
	m := ms[len(ms)-1]
	return &m
}

func (t *Tracker) GetErrorBudget(indicator Indicator) *ErrorBudget {
	target, ok := t.targets[indicator]
	if !ok {
		return nil
	}

	t.mu.RLock()
	defer t.mu.RUnlock()

	now := t.now()
	cutoff := now.Add(-t.windowSize)

	ms := t.measurements[indicator]
	var total, good int
	var earliest time.Time
	for _, m := range ms {
		if m.Timestamp.Before(cutoff) {
			continue
		}
		if total == 0 || m.Timestamp.Before(earliest) {
			earliest = m.Timestamp
		}
		total++
		if m.Good {
			good++
		}
	}

	if total == 0 {
		return &ErrorBudget{
			Indicator:       indicator,
			BudgetTotal:     target,
			BudgetConsumed:  0,
			BudgetRemaining: target,
			BurnRate:        0,
			MeasuredAt:      now,
		}
	}

	consumed := 1.0 - float64(good)/float64(total)
	remaining := target - consumed
	if remaining < 0 {
		remaining = 0
	}

	elapsed := now.Sub(earliest)
	windowFraction := elapsed.Seconds() / t.windowSize.Seconds()

	var burnRate float64
	if windowFraction > 0 {
		burnRate = consumed / windowFraction
	}

	return &ErrorBudget{
		Indicator:       indicator,
		BudgetTotal:     target,
		BudgetConsumed:  consumed,
		BudgetRemaining: remaining,
		BurnRate:        burnRate,
		MeasuredAt:      now,
	}
}

func (t *Tracker) GetAll() []ErrorBudget {
	var budgets []ErrorBudget
	for indicator := range t.targets {
		if b := t.GetErrorBudget(indicator); b != nil {
			budgets = append(budgets, *b)
		}
	}
	return budgets
}

func (t *Tracker) Prune() {
	t.mu.Lock()
	defer t.mu.Unlock()

	cutoff := t.now().Add(-t.windowSize)
	for indicator, ms := range t.measurements {
		kept := ms[:0]
		for _, m := range ms {
			if !m.Timestamp.Before(cutoff) {
				kept = append(kept, m)
			}
		}
		t.measurements[indicator] = kept
	}
}
