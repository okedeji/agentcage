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
	SourcePolicy     Source = "policy"
	SourceBehavioral Source = "behavioral"
)

type Category string

const (
	// Policy categories
	CategoryScopeViolation     Category = "scope_violation"
	CategoryCageConfigViolation Category = "cage_config_violation"
	CategoryComplianceViolation Category = "compliance_violation"

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
		Category:     Category(category),
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
	case SourceBehavioral:
		return intervention.TypeTripwireEscalation
	case SourcePolicy:
		return intervention.TypePolicyViolation
	default:
		return intervention.TypePolicyViolation
	}
}
