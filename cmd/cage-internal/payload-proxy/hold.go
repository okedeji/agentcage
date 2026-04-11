package main

import (
	"fmt"
	"sync"
	"time"
)

// HoldDecision is the outcome of a held payload review.
type HoldDecision int

const (
	HoldAllow HoldDecision = iota + 1
	HoldBlock
)

// HoldManager tracks payload requests that are paused waiting for a human
// decision. Each held request gets a channel; the proxy goroutine blocks
// on it until Release is called or the timeout expires.
type HoldManager struct {
	mu      sync.Mutex
	pending map[string]chan HoldDecision
	maxHeld int
}

func NewHoldManager(maxConcurrent int) *HoldManager {
	return &HoldManager{
		pending: make(map[string]chan HoldDecision),
		maxHeld: maxConcurrent,
	}
}

// Hold blocks the calling goroutine until a decision arrives or the timeout
// expires. Fail-closed: timeout returns HoldBlock.
func (m *HoldManager) Hold(holdID string, timeout time.Duration) HoldDecision {
	ch := make(chan HoldDecision, 1)

	m.mu.Lock()
	if len(m.pending) >= m.maxHeld {
		m.mu.Unlock()
		return HoldBlock
	}
	m.pending[holdID] = ch
	m.mu.Unlock()

	defer func() {
		m.mu.Lock()
		delete(m.pending, holdID)
		m.mu.Unlock()
	}()

	select {
	case decision := <-ch:
		return decision
	case <-time.After(timeout):
		return HoldBlock
	}
}

// Release sends a decision to a held request. Returns an error if the
// holdID is not found (already timed out or never existed).
func (m *HoldManager) Release(holdID string, decision HoldDecision) error {
	m.mu.Lock()
	ch, ok := m.pending[holdID]
	m.mu.Unlock()

	if !ok {
		return fmt.Errorf("hold %s not found", holdID)
	}

	select {
	case ch <- decision:
		return nil
	default:
		return fmt.Errorf("hold %s already resolved", holdID)
	}
}

// PendingCount returns how many requests are currently held.
func (m *HoldManager) PendingCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.pending)
}
