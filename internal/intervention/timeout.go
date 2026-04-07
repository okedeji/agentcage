package intervention

import (
	"context"
	"fmt"
	"time"

	"github.com/go-logr/logr"
)

type WorkflowSignaler interface {
	SignalWorkflow(ctx context.Context, workflowID, runID, signalName string, arg interface{}) error
}

type TimeoutEnforcer struct {
	queue        *Queue
	signaler     WorkflowSignaler
	pollInterval time.Duration
	logger       logr.Logger
}

func NewTimeoutEnforcer(queue *Queue, signaler WorkflowSignaler, pollInterval time.Duration, logger logr.Logger) *TimeoutEnforcer {
	return &TimeoutEnforcer{
		queue:        queue,
		signaler:     signaler,
		pollInterval: pollInterval,
		logger:       logger,
	}
}

func (e *TimeoutEnforcer) Run(ctx context.Context) error {
	ticker := time.NewTicker(e.pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			e.pollOnce(ctx)
		}
	}
}

func (e *TimeoutEnforcer) pollOnce(ctx context.Context) {
	expired := e.queue.GetExpired(time.Now())
	for _, req := range expired {
		log := e.logger.WithValues(
			"intervention_id", req.ID,
			"intervention_type", req.Type.String(),
			"cage_id", req.CageID,
			"assessment_id", req.AssessmentID,
		)
		log.Info("intervention timed out")

		if err := e.signalTimeout(ctx, req); err != nil {
			log.Error(err, "signaling workflow for timed out intervention")
		}

		if err := e.queue.TimeOut(ctx, req.ID); err != nil {
			log.Error(err, "marking intervention as timed out")
		}
	}
}

func (e *TimeoutEnforcer) signalTimeout(ctx context.Context, req *Request) error {
	switch req.Type {
	case TypeTripwireEscalation, TypePayloadReview:
		return e.signaler.SignalWorkflow(
			ctx,
			"cage-"+req.CageID,
			"",
			SignalIntervention,
			InterventionSignal{Action: ActionKill, Rationale: "intervention timeout"},
		)
	case TypeReportReview:
		return e.signaler.SignalWorkflow(
			ctx,
			"assessment-"+req.AssessmentID,
			"",
			SignalReportReview,
			ReportReviewSignal{Decision: ReviewReject, Rationale: "intervention timeout"},
		)
	case TypeProofGap:
		// Mirror the workflow's own internal timeout: skip the affected
		// findings so they fall through to the report review gate as
		// candidates. The workflow's waitForProofGap loop matches signals
		// by InterventionID, so the ID must be set.
		return e.signaler.SignalWorkflow(
			ctx,
			"assessment-"+req.AssessmentID,
			"",
			SignalProofGap,
			ProofGapSignal{
				InterventionID: req.ID,
				Action:         ProofGapActionSkip,
				Rationale:      "intervention timeout",
			},
		)
	default:
		return fmt.Errorf("unknown intervention type %d for timeout signaling", req.Type)
	}
}
