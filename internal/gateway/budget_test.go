package gateway

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBudgetEnforcer_UnderBudget(t *testing.T) {
	meter := NewTokenMeter()
	meter.Record("cage-1", "assess-1", "gpt-4", 100, 50)
	enforcer := NewBudgetEnforcer(meter)

	err := enforcer.Check("cage-1", 1000)
	require.NoError(t, err)
}

func TestBudgetEnforcer_AtBudget(t *testing.T) {
	meter := NewTokenMeter()
	meter.Record("cage-1", "assess-1", "gpt-4", 500, 500)
	enforcer := NewBudgetEnforcer(meter)

	err := enforcer.Check("cage-1", 1000)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrBudgetExhausted))
}

func TestBudgetEnforcer_OverBudget(t *testing.T) {
	meter := NewTokenMeter()
	meter.Record("cage-1", "assess-1", "gpt-4", 600, 500)
	enforcer := NewBudgetEnforcer(meter)

	err := enforcer.Check("cage-1", 1000)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrBudgetExhausted))
}

func TestBudgetEnforcer_RemainingUnderBudget(t *testing.T) {
	meter := NewTokenMeter()
	meter.Record("cage-1", "assess-1", "gpt-4", 100, 50)
	enforcer := NewBudgetEnforcer(meter)

	remaining := enforcer.Remaining("cage-1", 1000)
	assert.Equal(t, int64(850), remaining)
}

func TestBudgetEnforcer_RemainingOverBudget(t *testing.T) {
	meter := NewTokenMeter()
	meter.Record("cage-1", "assess-1", "gpt-4", 600, 500)
	enforcer := NewBudgetEnforcer(meter)

	remaining := enforcer.Remaining("cage-1", 1000)
	assert.Equal(t, int64(0), remaining)
}
