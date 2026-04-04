package assessment

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/go-logr/logr"

	"github.com/okedeji/agentcage/internal/cage"
	"github.com/okedeji/agentcage/internal/findings"
	"github.com/okedeji/agentcage/internal/gateway"
)

// ActivityImpl provides concrete implementations of all assessment
// lifecycle activities. It wires the cage server, findings store,
// planner, and playbook library together.
type ActivityImpl struct {
	cages       *cage.Service
	findings    findings.FindingStore
	bus         findings.Bus
	coordinator *findings.Coordinator
	planner     *Planner
	playbooks   *PlaybookLibrary
	log         logr.Logger
}

type ActivityImplConfig struct {
	Cages       *cage.Service
	Findings    findings.FindingStore
	Bus         findings.Bus
	Coordinator *findings.Coordinator
	LLMClient   *gateway.Client
	Playbooks   *PlaybookLibrary
	Log         logr.Logger
}

func NewActivityImpl(cfg ActivityImplConfig) *ActivityImpl {
	var planner *Planner
	if cfg.LLMClient != nil {
		planner = NewPlanner(cfg.LLMClient)
	}
	return &ActivityImpl{
		cages:       cfg.Cages,
		findings:    cfg.Findings,
		bus:         cfg.Bus,
		coordinator: cfg.Coordinator,
		planner:     planner,
		playbooks:   cfg.Playbooks,
		log:         cfg.Log.WithValues("component", "assessment-activities"),
	}
}

func (a *ActivityImpl) CreateDiscoveryCage(ctx context.Context, assessmentID string, config cage.Config) (string, error) {
	info, err := a.cages.CreateCage(ctx, config)
	if err != nil {
		return "", fmt.Errorf("creating discovery cage for assessment %s: %w", assessmentID, err)
	}
	a.log.Info("discovery cage created", "assessment_id", assessmentID, "cage_id", info.ID)
	return info.ID, nil
}

func (a *ActivityImpl) CreateValidatorCage(ctx context.Context, assessmentID string, finding findings.Finding, playbook *Playbook) (string, error) {
	config := cage.Config{
		AssessmentID:    assessmentID,
		Type:            cage.TypeValidator,
		Scope:           cage.Scope{Hosts: []string{finding.Endpoint}},
		ParentFindingID: finding.ID,
	}
	if playbook != nil {
		config.InputContext = []byte(playbook.Description)
	}
	info, err := a.cages.CreateCage(ctx, config)
	if err != nil {
		return "", fmt.Errorf("creating validator cage for finding %s: %w", finding.ID, err)
	}
	a.log.Info("validator cage created", "assessment_id", assessmentID, "cage_id", info.ID, "finding_id", finding.ID)
	return info.ID, nil
}

func (a *ActivityImpl) CreateEscalationCage(ctx context.Context, assessmentID string, finding findings.Finding, config cage.Config) (string, error) {
	info, err := a.cages.CreateCage(ctx, config)
	if err != nil {
		return "", fmt.Errorf("creating escalation cage for finding %s: %w", finding.ID, err)
	}
	a.log.Info("escalation cage created", "assessment_id", assessmentID, "cage_id", info.ID, "finding_id", finding.ID)
	return info.ID, nil
}

func (a *ActivityImpl) GetCandidateFindings(ctx context.Context, assessmentID string) ([]findings.Finding, error) {
	a.log.V(1).Info("fetching candidate findings", "assessment_id", assessmentID)
	return a.findings.GetByAssessment(ctx, assessmentID, findings.StatusCandidate)
}

func (a *ActivityImpl) GetValidatedFindings(ctx context.Context, assessmentID string) ([]findings.Finding, error) {
	a.log.V(1).Info("fetching validated findings", "assessment_id", assessmentID)
	return a.findings.GetByAssessment(ctx, assessmentID, findings.StatusValidated)
}

func (a *ActivityImpl) UpdateFindingStatus(ctx context.Context, findingID string, status findings.Status) error {
	a.log.Info("finding status updated", "finding_id", findingID, "status", status)
	return a.findings.UpdateStatus(ctx, findingID, status)
}

func (a *ActivityImpl) UpdateAssessmentStatus(ctx context.Context, assessmentID string, status Status) error {
	a.log.Info("assessment status updated", "assessment_id", assessmentID, "status", status)
	return nil
}

func (a *ActivityImpl) GenerateReport(ctx context.Context, assessmentID string, validated []findings.Finding) ([]byte, error) {
	report, err := GenerateReport(assessmentID, "", validated)
	if err != nil {
		return nil, fmt.Errorf("generating report for assessment %s: %w", assessmentID, err)
	}
	data, err := json.Marshal(report)
	if err != nil {
		return nil, fmt.Errorf("marshaling report for assessment %s: %w", assessmentID, err)
	}
	a.log.Info("report generated", "assessment_id", assessmentID, "findings_count", len(validated))
	return data, nil
}

func (a *ActivityImpl) PlanNextActions(ctx context.Context, state CoordinatorState) (CoordinatorDecision, error) {
	if a.planner == nil {
		return CoordinatorDecision{Done: true, Reason: "no LLM configured for coordinator"}, nil
	}
	decision, err := a.planner.PlanNextActions(ctx, state)
	if err != nil {
		return CoordinatorDecision{}, fmt.Errorf("planning next actions for assessment %s: %w", state.AssessmentID, err)
	}
	a.log.Info("coordinator decision",
		"assessment_id", state.AssessmentID,
		"iteration", state.Iteration,
		"done", decision.Done,
		"actions", len(decision.Actions),
	)
	return decision, nil
}
