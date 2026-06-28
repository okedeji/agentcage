package daemon

import (
	"testing"
	"time"

	"github.com/okedeji/agentcage/internal/history"
)

func TestEventBus_DeliversToSubscribers(t *testing.T) {
	b := newEventBus()
	ch, unsub := b.subscribe()
	defer unsub()

	b.publish(Event{Type: EventRunStarted, RunID: "echo-1"})
	select {
	case e := <-ch:
		if e.RunID != "echo-1" || e.Type != EventRunStarted {
			t.Errorf("got %+v", e)
		}
	case <-time.After(time.Second):
		t.Fatal("event was not delivered")
	}
}

func TestEventBus_UnsubscribeClosesChannel(t *testing.T) {
	b := newEventBus()
	ch, unsub := b.subscribe()
	unsub()
	if _, ok := <-ch; ok {
		t.Fatal("channel should be closed after unsubscribe")
	}
	// Publishing after the last unsubscribe is a no-op, never a send on a closed
	// channel.
	b.publish(Event{Type: EventRunEnded, RunID: "x"})
}

// TestEventBus_DropsForSlowSubscriber locks the fail-safe: a watcher that never
// drains must not block the publisher, so a stuck `agentcage events` client
// cannot wedge a run's lifecycle.
func TestEventBus_DropsForSlowSubscriber(t *testing.T) {
	b := newEventBus()
	_, unsub := b.subscribe() // never drained
	defer unsub()

	done := make(chan struct{})
	go func() {
		for i := 0; i < eventBufferSize*4; i++ {
			b.publish(Event{Type: EventRunStarted, RunID: "x"})
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("publish blocked on a slow subscriber")
	}
}

// TestFinish_PublishesEndedEvent locks that a run's close-out emits its event
// even with history off and no gateway to read spend from.
func TestFinish_PublishesEndedEvent(t *testing.T) {
	d := New()
	ch, unsub := d.events.subscribe()
	defer unsub()

	d.finish("echo-1", "@me/echo:1", history.StatusSucceeded, nil)
	select {
	case e := <-ch:
		if e.Type != EventRunEnded || e.RunID != "echo-1" || e.Status != history.StatusSucceeded {
			t.Errorf("got %+v", e)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no ended event")
	}
}
