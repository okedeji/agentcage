package intervention

import (
	"context"
	"fmt"
	"time"

	"github.com/go-logr/logr"
)

type Server struct {
	queue    *Queue
	signaler WorkflowSignaler
	logger   logr.Logger
}

func NewServer(queue *Queue, signaler WorkflowSignaler, logger logr.Logger) *Server {
	return &Server{
		queue:    queue,
		signaler: signaler,
		logger:   logger,
	}
}

func (s *Server) ListInterventions(ctx context.Context, filters ListFilters) ([]Request, error) {
	items, err := s.queue.List(ctx, filters)
	if err != nil {
		return nil, fmt.Errorf("listing interventions: %w", err)
	}
	return items, nil
}

func (s *Server) ResolveCageIntervention(ctx context.Context, interventionID string, action Action, rationale string, adjustments map[string]string, operatorID string) error {
	req, err := s.queue.store.GetIntervention(ctx, interventionID)
	if err != nil {
		return fmt.Errorf("getting intervention %s: %w", interventionID, err)
	}

	decision := Decision{
		InterventionID: interventionID,
		Action:         action,
		Rationale:      rationale,
		Adjustments:    adjustments,
		OperatorID:     operatorID,
		DecidedAt:      time.Now(),
	}

	if err := s.queue.Resolve(ctx, interventionID, decision); err != nil {
		return fmt.Errorf("resolving intervention %s: %w", interventionID, err)
	}

	if err := s.signaler.SignalWorkflow(
		ctx,
		"cage-"+req.CageID,
		"",
		SignalIntervention,
		InterventionSignal{
			Action:      action,
			Rationale:   rationale,
			Adjustments: adjustments,
		},
	); err != nil {
		return fmt.Errorf("signaling cage workflow for intervention %s: %w", interventionID, err)
	}

	s.logger.Info("cage intervention resolved",
		"intervention_id", interventionID,
		"cage_id", req.CageID,
		"action", action.String(),
		"operator_id", operatorID,
	)

	return nil
}

func (s *Server) ResolveAssessmentReview(ctx context.Context, interventionID string, decision ReviewDecision, rationale string, adjustments []FindingAdjustment, operatorID string) error {
	req, err := s.queue.store.GetIntervention(ctx, interventionID)
	if err != nil {
		return fmt.Errorf("getting intervention %s for review: %w", interventionID, err)
	}

	result := ReviewResult{
		InterventionID: interventionID,
		Decision:       decision,
		Rationale:      rationale,
		Adjustments:    adjustments,
		OperatorID:     operatorID,
		DecidedAt:      time.Now(),
	}

	if err := s.queue.ResolveReview(ctx, interventionID, result); err != nil {
		return fmt.Errorf("resolving review %s: %w", interventionID, err)
	}

	if err := s.signaler.SignalWorkflow(
		ctx,
		"assessment-"+req.AssessmentID,
		"",
		SignalReportReview,
		ReportReviewSignal{
			Decision:    decision,
			Rationale:   rationale,
			Adjustments: adjustments,
		},
	); err != nil {
		return fmt.Errorf("signaling assessment workflow for review %s: %w", interventionID, err)
	}

	s.logger.Info("assessment review resolved",
		"intervention_id", interventionID,
		"assessment_id", req.AssessmentID,
		"decision", decision.String(),
		"operator_id", operatorID,
	)

	return nil
}
