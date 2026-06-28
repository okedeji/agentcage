package daemon

import (
	"encoding/json"
	"net/http"
	"sync"
	"time"
)

// Event is one entry on the `agentcage events` live feed. Type names the
// transition; the rest carries enough to read the feed without a second lookup.
// The bus is the single sink for lifecycle events, so new event types (sub-agent
// activation, elicitation) publish through it as they gain a daemon-side hook.
type Event struct {
	Time   time.Time `json:"time"`
	Type   string    `json:"type"`
	RunID  string    `json:"run_id"`
	Ref    string    `json:"ref,omitempty"`
	Target string    `json:"target,omitempty"`
	Status string    `json:"status,omitempty"`
	Detail string    `json:"detail,omitempty"`
}

// Event types. The run lifecycle pair is emitted by the daemon; the rest come
// from the runtime (sub-agent activation, eviction, elicitation) through the
// run's OnEvent hook.
const (
	EventRunStarted = "run.started"
	EventRunEnded   = "run.ended"
)

// eventBufferSize bounds each subscriber's queue. A watcher that falls this far
// behind is dropped from rather than allowed to block the publisher: losing an
// event on a stuck `agentcage events` client is acceptable, stalling a run's
// lifecycle on it is not.
const eventBufferSize = 256

// eventBus fans out events to every live subscriber. publish never blocks; a
// subscriber whose buffer is full loses the event.
type eventBus struct {
	mu   sync.Mutex
	next int
	subs map[int]chan Event
}

func newEventBus() *eventBus {
	return &eventBus{subs: map[int]chan Event{}}
}

// subscribe registers a watcher and returns its channel and an unsubscribe to
// defer. unsubscribe closes the channel, so a ranging reader ends cleanly.
func (b *eventBus) subscribe() (<-chan Event, func()) {
	ch := make(chan Event, eventBufferSize)
	b.mu.Lock()
	id := b.next
	b.next++
	b.subs[id] = ch
	b.mu.Unlock()
	return ch, func() {
		b.mu.Lock()
		if c, ok := b.subs[id]; ok {
			delete(b.subs, id)
			close(c)
		}
		b.mu.Unlock()
	}
}

// publish delivers e to every subscriber, dropping it for any whose buffer is
// full. Send and close are both under the lock, so publish never sends on a
// closed channel: unsubscribe deletes from the map before closing.
func (b *eventBus) publish(e Event) {
	if b == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, ch := range b.subs {
		select {
		case ch <- e:
		default:
		}
	}
}

// handleEvents streams the event feed to a client until it disconnects. The
// subscriber is registered before the first write and dropped on return, so a
// client that hangs up frees its slot.
func (d *Daemon) handleEvents(w http.ResponseWriter, r *http.Request) {
	ch, unsub := d.events.subscribe()
	defer unsub()

	w.Header().Set("Content-Type", "application/x-ndjson")
	w.WriteHeader(http.StatusOK)
	flusher, _ := w.(http.Flusher)
	if flusher != nil {
		flusher.Flush()
	}
	enc := json.NewEncoder(w)
	for {
		select {
		case <-r.Context().Done():
			return
		case e, ok := <-ch:
			if !ok {
				return
			}
			if err := enc.Encode(e); err != nil {
				return
			}
			if flusher != nil {
				flusher.Flush()
			}
		}
	}
}
