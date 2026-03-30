package enforcement

import (
	"context"
	"sync"
	"time"
)

type PendingPayload struct {
	Payload  ClassificationPayload
	ResultCh chan<- ClassificationResult
}

type PayloadBatcher struct {
	client   *ClassificationClient
	window   time.Duration
	maxBatch int
	mu       sync.Mutex
	pending  []PendingPayload
	timer    *time.Timer
}

func NewPayloadBatcher(client *ClassificationClient, window time.Duration, maxBatch int) *PayloadBatcher {
	return &PayloadBatcher{
		client:   client,
		window:   window,
		maxBatch: maxBatch,
	}
}

func (b *PayloadBatcher) Submit(payload ClassificationPayload) <-chan ClassificationResult {
	ch := make(chan ClassificationResult, 1)

	b.mu.Lock()
	b.pending = append(b.pending, PendingPayload{
		Payload:  payload,
		ResultCh: ch,
	})

	if len(b.pending) >= b.maxBatch {
		pending := b.takePendingLocked()
		b.mu.Unlock()
		go b.flushBatch(pending)
		return ch
	}

	if len(b.pending) == 1 {
		b.timer = time.AfterFunc(b.window, func() {
			b.mu.Lock()
			pending := b.takePendingLocked()
			b.mu.Unlock()
			if len(pending) > 0 {
				b.flushBatch(pending)
			}
		})
	}

	b.mu.Unlock()
	return ch
}

func (b *PayloadBatcher) takePendingLocked() []PendingPayload {
	pending := b.pending
	b.pending = nil
	if b.timer != nil {
		b.timer.Stop()
		b.timer = nil
	}
	return pending
}

func (b *PayloadBatcher) flushBatch(pending []PendingPayload) {
	payloads := make([]ClassificationPayload, len(pending))
	for i, p := range pending {
		payloads[i] = p.Payload
	}

	results, err := b.client.Classify(context.Background(), payloads)
	if err != nil {
		for _, p := range pending {
			p.ResultCh <- ClassificationResult{Safe: false, Confidence: 0, Reason: err.Error()}
		}
		return
	}

	for i, p := range pending {
		p.ResultCh <- results[i]
	}
}

func (b *PayloadBatcher) Close() {
	b.mu.Lock()
	pending := b.takePendingLocked()
	b.mu.Unlock()
	if len(pending) > 0 {
		b.flushBatch(pending)
	}
}
