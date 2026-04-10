package alert

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/go-logr/logr"
	"github.com/google/uuid"

	"github.com/okedeji/agentcage/internal/intervention"
)

type Source string

const (
	SourcePolicy     Source = "policy"
	SourceBehavioral Source = "behavioral"
)

type Category string

const (
	// Policy categories
	CategoryScopeViolation     Category = "scope_violation"
	CategoryCageConfigViolation Category = "cage_config_violation"

	// Behavioral categories
	CategoryPrivilegedShell     Category = "privileged_shell"
	CategoryAnyShell            Category = "any_shell"
	CategorySensitiveFileWrite  Category = "sensitive_file_write"
	CategoryAnyFileWrite        Category = "any_file_write"
	CategoryPrivilegeEscalation Category = "privilege_escalation"
	CategoryForkBomb            Category = "fork_bomb"
	CategoryUnexpectedNetwork   Category = "unexpected_network"
	CategoryLateralMovement     Category = "lateral_movement"
	CategoryUnexpectedProcess   Category = "unexpected_process"
	CategoryKernelModule        Category = "kernel_module"
	CategoryPtrace              Category = "ptrace"
	CategoryMount               Category = "mount"
	CategoryContainerEscape     Category = "container_escape"
	CategoryRawSocket           Category = "raw_socket"
	CategoryDNSExfil            Category = "dns_exfil"
	CategoryLargeRead           Category = "large_read"
	CategoryPersistence         Category = "persistence"
	CategoryDownloadExec        Category = "download_exec"
)

type Event struct {
	Source       Source
	Category    Category
	Priority    intervention.Priority
	CageID      string
	AssessmentID string
	Description string
	Details     map[string]any
}

// Dispatcher routes alert events through the intervention notification system.
// Dispatch is asynchronous (fire-and-forget) so it never blocks the caller.
// Critical alerts are always accepted. Normal alerts are dropped when the
// queue is full, with a suppression count reported on the next successful send.
type Dispatcher struct {
	notifier   intervention.Notifier
	log        logr.Logger
	critical   chan Event
	normal     chan Event
	suppressed int64
	mu         sync.Mutex
	done       sync.WaitGroup
}

func NewDispatcher(notifier intervention.Notifier, log logr.Logger) *Dispatcher {
	d := &Dispatcher{
		notifier: notifier,
		log:      log.WithValues("component", "alert-dispatcher"),
		critical: make(chan Event, 50),
		normal:   make(chan Event, 100),
	}
	d.done.Add(1)
	go d.processQueues()
	return d
}

// Close stops accepting new alerts, drains remaining queued alerts, and
// waits for the background goroutine to finish.
func (d *Dispatcher) Close() {
	close(d.critical)
	close(d.normal)
	d.done.Wait()
}

func (d *Dispatcher) processQueues() {
	defer d.done.Done()

	for {
		// Critical alerts are always drained first
		select {
		case event, ok := <-d.critical:
			if !ok {
				d.drainNormal()
				return
			}
			d.send(event)
		default:
			select {
			case event, ok := <-d.critical:
				if !ok {
					d.drainNormal()
					return
				}
				d.send(event)
			case event, ok := <-d.normal:
				if !ok {
					d.drainCritical()
					return
				}
				d.send(event)
			}
		}
	}
}

func (d *Dispatcher) drainNormal() {
	for event := range d.normal {
		d.send(event)
	}
}

func (d *Dispatcher) drainCritical() {
	for event := range d.critical {
		d.send(event)
	}
}

func (d *Dispatcher) send(event Event) {
	d.mu.Lock()
	suppressed := d.suppressed
	d.suppressed = 0
	d.mu.Unlock()

	contextData, _ := json.Marshal(event.Details)
	desc := fmt.Sprintf("[%s/%s] %s", event.Source, event.Category, event.Description)
	if suppressed > 0 {
		desc += fmt.Sprintf(" [%d alerts suppressed]", suppressed)
	}

	req := intervention.Request{
		ID:           uuid.NewString(),
		Type:         interventionType(event.Source),
		Status:       intervention.StatusResolved,
		Priority:     event.Priority,
		CageID:       event.CageID,
		AssessmentID: event.AssessmentID,
		Description:  desc,
		ContextData:  contextData,
		Timeout:      0,
		CreatedAt:    time.Now(),
	}

	if err := d.notifier.NotifyCreated(context.Background(), req); err != nil {
		d.log.Error(err, "sending alert notification")
	}
}

// Notify satisfies the cage.AlertNotifier interface, allowing the cage
// package to dispatch alerts without importing this package directly.
func (d *Dispatcher) Notify(ctx context.Context, source, category, description, cageID, assessmentID string, priority int, details map[string]any) {
	d.Dispatch(ctx, Event{
		Source:       Source(source),
		Category:     Category(category),
		Priority:     intervention.Priority(priority),
		CageID:       cageID,
		AssessmentID: assessmentID,
		Description:  description,
		Details:      details,
	})
}

// Dispatch sends an alert asynchronously. Critical and high priority alerts
// always queue. Normal alerts are dropped when the queue is full.
func (d *Dispatcher) Dispatch(_ context.Context, event Event) {
	d.log.Info("alert dispatched",
		"source", event.Source,
		"category", event.Category,
		"priority", event.Priority,
		"cage_id", event.CageID,
		"assessment_id", event.AssessmentID,
	)

	if event.Priority >= intervention.PriorityHigh {
		d.critical <- event
		return
	}

	select {
	case d.normal <- event:
	default:
		d.mu.Lock()
		d.suppressed++
		d.mu.Unlock()
		d.log.V(1).Info("alert suppressed (queue full)",
			"source", event.Source,
			"category", event.Category,
		)
	}
}

func interventionType(source Source) intervention.Type {
	switch source {
	case SourceBehavioral:
		return intervention.TypeTripwireEscalation
	case SourcePolicy:
		return intervention.TypePolicyViolation
	default:
		return intervention.TypePolicyViolation
	}
}
