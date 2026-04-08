package intervention

import (
	"context"
	"fmt"
	"time"

	"github.com/go-logr/logr"
)

// ProofReloader is implemented by anything that can re-read the
// on-disk proof library. Kept as an interface so this package doesn't
// import assessment and create a cycle.
type ProofReloader interface {
	Reload() error
}

type Service struct {
	queue        *Queue
	signaler     WorkflowSignaler
	proofLibrary ProofReloader
	logger       logr.Logger
}

func NewService(queue *Queue, signaler WorkflowSignaler, logger logr.Logger) *Service {
	return &Service{
		queue:    queue,
		signaler: signaler,
		logger:   logger,
	}
}

// SetProofReloader installs the proof library so retry resolutions of
// proof_gap interventions reload it from disk before signaling the
// workflow. Optional. If unset, retry re-runs lookup against whatever
// is currently in memory.
func (s *Service) SetProofReloader(p ProofReloader) {
	s.proofLibrary = p
}

// EnqueueProofGap creates a pending proof_gap intervention scoped to an
// assessment. Used by the validation phase activity when no proof matches a
// candidate finding's vulnerability class.
func (s *Service) EnqueueProofGap(ctx context.Context, assessmentID, description string, contextData []byte, timeout time.Duration) (*Request, error) {
	return s.queue.Enqueue(ctx, TypeProofGap, PriorityHigh, "", assessmentID, description, contextData, timeout)
}

// ResolveProofGap resolves a pending proof_gap intervention. On retry, the
// proof library is reloaded from disk before signaling the workflow so the
// next lookup pass sees any newly-added proofs.
func (s *Service) ResolveProofGap(ctx context.Context, interventionID string, action ProofGapAction, rationale, operatorID string) error {
	req, err := s.queue.store.GetIntervention(ctx, interventionID)
	if err != nil {
		return fmt.Errorf("getting intervention %s: %w", interventionID, err)
	}
	if req.Type != TypeProofGap {
		return fmt.Errorf("intervention %s is type %s, not proof_gap", interventionID, req.Type)
	}

	// Reload proofs BEFORE signaling so the workflow's retry lookup sees any
	// new YAML files the operator added via `agentcage proof add`.
	if action == ProofGapActionRetry && s.proofLibrary != nil {
		if err := s.proofLibrary.Reload(); err != nil {
			return fmt.Errorf("reloading proof library before retry: %w", err)
		}
	}

	decision := Decision{
		InterventionID: interventionID,
		Action:         ActionResume, // reused for the queue bookkeeping path
		Rationale:      rationale,
		OperatorID:     operatorID,
		DecidedAt:      time.Now(),
	}
	if err := s.queue.Resolve(ctx, interventionID, decision); err != nil {
		return fmt.Errorf("resolving proof_gap intervention %s: %w", interventionID, err)
	}

	if err := s.signaler.SignalWorkflow(
		ctx,
		"assessment-"+req.AssessmentID,
		"",
		SignalProofGap,
		ProofGapSignal{
			InterventionID: interventionID,
			Action:         action,
			Rationale:      rationale,
		},
	); err != nil {
		return fmt.Errorf("signaling assessment workflow for proof_gap %s: %w", interventionID, err)
	}

	s.logger.Info("proof_gap intervention resolved",
		"intervention_id", interventionID,
		"assessment_id", req.AssessmentID,
		"action", action.String(),
		"operator_id", operatorID,
	)
	return nil
}

func (s *Service) ListInterventions(ctx context.Context, filters ListFilters) ([]Request, error) {
	items, err := s.queue.List(ctx, filters)
	if err != nil {
		return nil, fmt.Errorf("listing interventions: %w", err)
	}
	return items, nil
}

func (s *Service) ResolveCageIntervention(ctx context.Context, interventionID string, action Action, rationale string, adjustments map[string]string, operatorID string) error {
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

func (s *Service) ResolveAssessmentReview(ctx context.Context, interventionID string, decision ReviewDecision, rationale string, adjustments []FindingAdjustment, operatorID string) error {
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
