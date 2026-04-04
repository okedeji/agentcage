package alert

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-logr/logr"
	"github.com/google/uuid"

	"github.com/okedeji/agentcage/internal/intervention"
)

type Source string

const (
	SourcePolicy Source = "policy"
	SourceFalco  Source = "falco"
)

type Event struct {
	Source       Source
	Category    string // "scope", "cage_config", "compliance", "privilege_escalation", etc.
	Priority    intervention.Priority
	CageID      string
	AssessmentID string
	Description string
	Details     map[string]any
}

// Dispatcher routes alert events through the intervention notification system.
type Dispatcher struct {
	notifier intervention.Notifier
	log      logr.Logger
}

func NewDispatcher(notifier intervention.Notifier, log logr.Logger) *Dispatcher {
	return &Dispatcher{
		notifier: notifier,
		log:      log.WithValues("component", "alert-dispatcher"),
	}
}

// Notify satisfies the cage.AlertNotifier interface, allowing the cage
// package to dispatch alerts without importing this package directly.
func (d *Dispatcher) Notify(ctx context.Context, source, category, description, cageID, assessmentID string, priority int, details map[string]any) {
	d.Dispatch(ctx, Event{
		Source:       Source(source),
		Category:     category,
		Priority:     intervention.Priority(priority),
		CageID:       cageID,
		AssessmentID: assessmentID,
		Description:  description,
		Details:      details,
	})
}

func (d *Dispatcher) Dispatch(ctx context.Context, event Event) {
	contextData, _ := json.Marshal(event.Details)

	req := intervention.Request{
		ID:           uuid.NewString(),
		Type:         interventionType(event.Source),
		Status:       intervention.StatusResolved,
		Priority:     event.Priority,
		CageID:       event.CageID,
		AssessmentID: event.AssessmentID,
		Description:  fmt.Sprintf("[%s/%s] %s", event.Source, event.Category, event.Description),
		ContextData:  contextData,
		Timeout:      0,
		CreatedAt:    time.Now(),
	}

	d.log.Info("alert dispatched",
		"source", event.Source,
		"category", event.Category,
		"priority", event.Priority,
		"cage_id", event.CageID,
		"assessment_id", event.AssessmentID,
	)

	if err := d.notifier.NotifyCreated(ctx, req); err != nil {
		d.log.Error(err, "sending alert notification")
	}
}

func interventionType(source Source) intervention.Type {
	switch source {
	case SourceFalco:
		return intervention.TypeTripwireEscalation
	case SourcePolicy:
		return intervention.TypePolicyViolation
	default:
		return intervention.TypePolicyViolation
	}
}
