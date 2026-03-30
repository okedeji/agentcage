package rca

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerate_TimeoutReason(t *testing.T) {
	doc := Generate("cage-1", "assess-1", "cage timeout exceeded", nil)
	assert.Contains(t, doc.Impact, "time limit")
	assert.Contains(t, doc.Remediation, "increasing the time limit")
}

func TestGenerate_TripwireReason(t *testing.T) {
	doc := Generate("cage-1", "assess-1", "tripwire fired on suspicious syscall", nil)
	assert.Contains(t, doc.Impact, "behavioral anomaly")
	assert.Contains(t, doc.Remediation, "Falco alert")
}

func TestGenerate_TokenBudgetReason(t *testing.T) {
	doc := Generate("cage-1", "assess-1", "token budget exhausted", nil)
	assert.Contains(t, doc.Impact, "token budget")
	assert.Contains(t, doc.Remediation, "token budget")
}

func TestGenerate_BudgetReason(t *testing.T) {
	doc := Generate("cage-1", "assess-1", "LLM budget depleted", nil)
	assert.Contains(t, doc.Impact, "token budget")
	assert.Contains(t, doc.Remediation, "token budget")
}

func TestGenerate_ProvisionReason(t *testing.T) {
	doc := Generate("cage-1", "assess-1", "provision failed: no hosts available", nil)
	assert.Contains(t, doc.Impact, "failed to provision")
	assert.Contains(t, doc.Remediation, "host capacity")
}

func TestGenerate_UnknownReason(t *testing.T) {
	doc := Generate("cage-1", "assess-1", "unexpected internal error", nil)
	assert.Contains(t, doc.Impact, "failed during execution")
	assert.Contains(t, doc.Remediation, "audit log timeline")
}

func TestGenerate_DocumentFields(t *testing.T) {
	timeline := []TimelineEntry{
		{Timestamp: time.Now().Add(-2 * time.Minute), Event: "started", Details: "cage started"},
		{Timestamp: time.Now().Add(-1 * time.Minute), Event: "failed", Details: "cage failed"},
	}

	doc := Generate("cage-42", "assess-99", "timeout during discovery", timeline)

	require.NotEmpty(t, doc.ID)
	assert.Equal(t, "cage-42", doc.CageID)
	assert.Equal(t, "assess-99", doc.AssessmentID)
	assert.Equal(t, "timeout during discovery", doc.Summary)
	assert.Equal(t, "timeout during discovery", doc.RootCause)
	assert.False(t, doc.CreatedAt.IsZero())
	require.Len(t, doc.Timeline, 2)
	assert.Equal(t, "started", doc.Timeline[0].Event)
	assert.Equal(t, "failed", doc.Timeline[1].Event)
}
