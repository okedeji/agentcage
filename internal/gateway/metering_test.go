package gateway

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTokenMeter_RecordAndGetUsage(t *testing.T) {
	m := NewTokenMeter()
	m.Record("cage-1", "assess-1", "gpt-4", 100, 50)

	usage := m.GetUsage("cage-1")
	assert.Equal(t, "cage-1", usage.CageID)
	assert.Equal(t, int64(100), usage.InputTokens)
	assert.Equal(t, int64(50), usage.OutputTokens)
}

func TestTokenMeter_MultipleRecordsAccumulate(t *testing.T) {
	m := NewTokenMeter()
	m.Record("cage-1", "assess-1", "gpt-4", 100, 50)
	m.Record("cage-1", "assess-1", "gpt-4", 200, 75)
	m.Record("cage-1", "assess-1", "gpt-4", 50, 25)

	usage := m.GetUsage("cage-1")
	assert.Equal(t, int64(350), usage.InputTokens)
	assert.Equal(t, int64(150), usage.OutputTokens)
}

func TestTokenMeter_UnknownCageReturnsZero(t *testing.T) {
	m := NewTokenMeter()

	usage := m.GetUsage("nonexistent")
	assert.Equal(t, "nonexistent", usage.CageID)
	assert.Equal(t, int64(0), usage.InputTokens)
	assert.Equal(t, int64(0), usage.OutputTokens)
}

func TestTokenMeter_ResetClearsCage(t *testing.T) {
	m := NewTokenMeter()
	m.Record("cage-1", "assess-1", "gpt-4", 100, 50)
	m.Reset("cage-1")

	usage := m.GetUsage("cage-1")
	assert.Equal(t, int64(0), usage.InputTokens)
	assert.Equal(t, int64(0), usage.OutputTokens)
}

func TestTokenMeter_ConcurrentRecording(t *testing.T) {
	m := NewTokenMeter()

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m.Record("cage-1", "assess-1", "gpt-4", 10, 5)
		}()
	}
	wg.Wait()

	usage := m.GetUsage("cage-1")
	assert.Equal(t, int64(1000), usage.InputTokens)
	assert.Equal(t, int64(500), usage.OutputTokens)
}
