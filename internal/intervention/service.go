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

// PayloadHoldResolver relays hold decisions back to the in-cage proxy.
// Defined here as an interface so the concrete implementation in cage/
// does not create an import cycle.
type PayloadHoldResolver interface {
	ReleaseHold(ctx context.Context, interventionID string, allow bool) error
}

// AgentHoldResolver relays hold decisions back to the agent inside the
// cage via the vsock-backed AgentHoldListener. Same pattern as
// PayloadHoldResolver but for agent-initiated holds.
type AgentHoldResolver interface {
	ResolveHold(interventionID string, allowed bool, message string) error
}

type Service struct {
	queue               *Queue
	signaler            WorkflowSignaler
	proofLibrary        ProofReloader
	payloadHoldResolver PayloadHoldResolver
	agentHoldResolver   AgentHoldResolver
	logger              logr.Logger
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

// SetPayloadHoldResolver installs the resolver that relays payload hold
// decisions back to the in-cage proxy. Optional: if unset, payload hold
// interventions are resolved in the queue but the proxy times out.
func (s *Service) SetPayloadHoldResolver(r PayloadHoldResolver) {
	s.payloadHoldResolver = r
}

// SetAgentHoldResolver installs the resolver that relays agent hold
// decisions back to the agent via vsock. Optional: if unset, agent hold
// interventions are resolved in the queue but the agent times out.
func (s *Service) SetAgentHoldResolver(r AgentHoldResolver) {
	s.agentHoldResolver = r
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
	if req == nil {
		return fmt.Errorf("intervention %s not found", interventionID)
	}
	if req.Type != TypeProofGap {
		return fmt.Errorf("intervention %s is type %s, not proof_gap", interventionID, req.Type)
	}

	// Reload proofs BEFORE signaling so the workflow's retry lookup sees any
	// new YAML files the operator added via `agentcage proof add`.
	if action == ProofGapActionRetry && s.proofLibrary != nil {
		if err := s.proofLibrary.Reload(); err != nil {
			s.logger.Error(err, "reloading proof library before retry, continuing with existing proofs",
				"intervention_id", interventionID)
		} else {
			s.logger.Info("proof library reloaded for retry",
				"intervention_id", interventionID)
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

func (s *Service) GetIntervention(ctx context.Context, id string) (*Request, error) {
	return s.queue.Get(ctx, id)
}

func (s *Service) ListInterventions(ctx context.Context, filters ListFilters) ([]Request, string, error) {
	items, nextToken, err := s.queue.List(ctx, filters)
	if err != nil {
		return nil, "", fmt.Errorf("listing interventions: %w", err)
	}
	return items, nextToken, nil
}

func (s *Service) ResolveCageIntervention(ctx context.Context, interventionID string, action Action, rationale string, adjustments map[string]string, operatorID string) error {
	req, err := s.queue.store.GetIntervention(ctx, interventionID)
	if err != nil {
		return fmt.Errorf("getting intervention %s: %w", interventionID, err)
	}
	if req == nil {
		return fmt.Errorf("intervention %s not found", interventionID)
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

	// Payload hold decisions also need to reach the proxy inside the VM.
	// The workflow signal handles ActionKill (tears down the cage); Allow
	// and Block go directly to the proxy's control endpoint.
	if req.Type == TypePayloadReview && s.payloadHoldResolver != nil {
		allow := action == ActionAllow
		if err := s.payloadHoldResolver.ReleaseHold(ctx, interventionID, allow); err != nil {
			s.logger.Error(err, "relaying payload hold decision to proxy", "intervention_id", interventionID)
		}
	}

	// Agent hold decisions go back to the agent over the vsock hold
	// connection. The agent is blocked on a socket read; this unblocks it.
	if req.Type == TypeAgentHold && s.agentHoldResolver != nil {
		allowed := action == ActionAllow || action == ActionResume
		if err := s.agentHoldResolver.ResolveHold(interventionID, allowed, rationale); err != nil {
			s.logger.Error(err, "relaying agent hold decision", "intervention_id", interventionID)
		}
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
	if req == nil {
		return fmt.Errorf("intervention %s not found", interventionID)
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
