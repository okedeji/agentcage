package fleet

import "sync"

type DemandLedger struct {
	mu      sync.RWMutex
	demands map[string]int32
}

func NewDemandLedger() *DemandLedger {
	return &DemandLedger{
		demands: make(map[string]int32),
	}
}

func (dl *DemandLedger) AddDemand(assessmentID string, expectedPeak int32) {
	dl.mu.Lock()
	defer dl.mu.Unlock()

	dl.demands[assessmentID] = expectedPeak
}

func (dl *DemandLedger) RemoveDemand(assessmentID string) {
	dl.mu.Lock()
	defer dl.mu.Unlock()

	delete(dl.demands, assessmentID)
}

func (dl *DemandLedger) CurrentDemand() int32 {
	dl.mu.RLock()
	defer dl.mu.RUnlock()

	var total int32
	for _, peak := range dl.demands {
		total += peak
	}
	return total
}

func (dl *DemandLedger) GetDemand(assessmentID string) int32 {
	dl.mu.RLock()
	defer dl.mu.RUnlock()

	return dl.demands[assessmentID]
}
