package main

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHoldManager_AllowRelease(t *testing.T) {
	mgr := NewHoldManager(10)
	done := make(chan HoldDecision, 1)

	go func() {
		done <- mgr.Hold("h-1", 5*time.Second)
	}()

	// Brief delay for the goroutine to register the hold.
	time.Sleep(50 * time.Millisecond)
	require.Equal(t, 1, mgr.PendingCount())

	err := mgr.Release("h-1", HoldAllow)
	require.NoError(t, err)

	decision := <-done
	assert.Equal(t, HoldAllow, decision)
	assert.Equal(t, 0, mgr.PendingCount())
}

func TestHoldManager_BlockRelease(t *testing.T) {
	mgr := NewHoldManager(10)
	done := make(chan HoldDecision, 1)

	go func() {
		done <- mgr.Hold("h-2", 5*time.Second)
	}()

	time.Sleep(50 * time.Millisecond)
	err := mgr.Release("h-2", HoldBlock)
	require.NoError(t, err)

	decision := <-done
	assert.Equal(t, HoldBlock, decision)
}

func TestHoldManager_Timeout(t *testing.T) {
	mgr := NewHoldManager(10)

	start := time.Now()
	decision := mgr.Hold("h-3", 200*time.Millisecond)
	elapsed := time.Since(start)

	assert.Equal(t, HoldBlock, decision, "timeout should fail-closed with block")
	assert.GreaterOrEqual(t, elapsed, 200*time.Millisecond)
	assert.Equal(t, 0, mgr.PendingCount(), "timed-out hold should be cleaned up")
}

func TestHoldManager_MaxConcurrent(t *testing.T) {
	mgr := NewHoldManager(2)

	go func() { mgr.Hold("h-a", 5*time.Second) }()
	go func() { mgr.Hold("h-b", 5*time.Second) }()
	time.Sleep(50 * time.Millisecond)

	decision := mgr.Hold("h-c", 5*time.Second)
	assert.Equal(t, HoldBlock, decision, "should fail-closed when at max capacity")
}

func TestHoldManager_ReleaseUnknown(t *testing.T) {
	mgr := NewHoldManager(10)
	err := mgr.Release("nonexistent", HoldAllow)
	assert.Error(t, err)
}
