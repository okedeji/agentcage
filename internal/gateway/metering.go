package gateway

import (
	"sync"
	"sync/atomic"
)

type TokenMeter struct {
	mu    sync.RWMutex
	cages map[string]*cageMetrics
}

type cageMetrics struct {
	inputTokens  atomic.Int64
	outputTokens atomic.Int64
}

func NewTokenMeter() *TokenMeter {
	return &TokenMeter{cages: make(map[string]*cageMetrics)}
}

func (m *TokenMeter) Record(cageID, model string, input, output int64) {
	m.mu.RLock()
	cm, ok := m.cages[cageID]
	m.mu.RUnlock()

	if !ok {
		m.mu.Lock()
		cm, ok = m.cages[cageID]
		if !ok {
			cm = &cageMetrics{}
			m.cages[cageID] = cm
		}
		m.mu.Unlock()
	}

	cm.inputTokens.Add(input)
	cm.outputTokens.Add(output)
}

func (m *TokenMeter) GetUsage(cageID string) TokenUsage {
	m.mu.RLock()
	cm, ok := m.cages[cageID]
	m.mu.RUnlock()

	if !ok {
		return TokenUsage{CageID: cageID}
	}

	return TokenUsage{
		CageID:       cageID,
		InputTokens:  cm.inputTokens.Load(),
		OutputTokens: cm.outputTokens.Load(),
	}
}

func (m *TokenMeter) Reset(cageID string) {
	m.mu.Lock()
	delete(m.cages, cageID)
	m.mu.Unlock()
}
