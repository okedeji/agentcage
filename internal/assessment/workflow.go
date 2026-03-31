package assessment

import (
	"fmt"
	"time"

	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/workflow"

	"github.com/okedeji/agentcage/internal/cage"
	"github.com/okedeji/agentcage/internal/findings"
	"github.com/okedeji/agentcage/internal/intervention"
)

const (
	WorkflowName = "AssessmentLifecycle"

	TimeoutCreateCage      = 30 * time.Second
	TimeoutGetFindings     = 15 * time.Second
	TimeoutUpdateStatus    = 5 * time.Second
	TimeoutGenerateReport  = 30 * time.Second
	TimeoutUpdateFinding   = 5 * time.Second
	TimeoutPlanNextActions = 60 * time.Second
	TimeoutReviewDeadline  = 24 * time.Hour
	TimeoutWaitForCage     = 10 * time.Minute
	DefaultMaxConcurrent   = int32(10)
	DefaultMaxChainDepth   = int32(3)
	DefaultMaxIterations   = int32(20)
)

type AssessmentWorkflowInput struct {
	AssessmentID  string
	Config        Config
	MaxIterations int32
}

type AssessmentWorkflowResult struct {
	AssessmentID string
	FinalStatus  Status
	TotalCages   int32
	Findings     int32
	Iterations   int32
	Error        string
}

func AssessmentWorkflow(ctx workflow.Context, input AssessmentWorkflowInput) (AssessmentWorkflowResult, error) {
	result := AssessmentWorkflowResult{AssessmentID: input.AssessmentID}
	cfg := input.Config

	maxIterations := input.MaxIterations
	if maxIterations <= 0 {
		maxIterations = DefaultMaxIterations
	}

	maxChainDepth := cfg.MaxChainDepth
	if maxChainDepth <= 0 {
		maxChainDepth = DefaultMaxChainDepth
	}

	// ===== Phase 1: Initial surface mapping (deterministic) =====

	if err := updateStatus(ctx, input.AssessmentID, StatusDiscovery); err != nil {
		return failResult(result, "updating status to mapping: %v", err), nil
	}

	discoveryCageID, err := createDiscoveryCage(ctx, input.AssessmentID, cfg)
	if err != nil {
		return failResult(result, "creating discovery cage for surface mapping: %v", err), nil
	}
	result.TotalCages++
	_ = discoveryCageID

	if err := workflow.Sleep(ctx, TimeoutWaitForCage); err != nil {
		return failResult(result, "waiting for surface mapping cage: %v", err), nil
	}

	// ===== Phase 2: LLM-driven coordinator loop =====

	if err := updateStatus(ctx, input.AssessmentID, StatusExploitation); err != nil {
		return failResult(result, "updating status to testing: %v", err), nil
	}

	coverage := make(map[string][]string)
	var cagesCompleted []CageSummary
	startTime := workflow.Now(ctx)

	for iteration := int32(0); iteration < maxIterations; iteration++ {
		result.Iterations = iteration + 1

		allFindings, err := getAllFindings(ctx, input.AssessmentID)
		if err != nil {
			return failResult(result, "fetching findings for coordinator (iteration %d): %v", iteration, err), nil
		}

		elapsed := workflow.Now(ctx).Sub(startTime)

		state := CoordinatorState{
			AssessmentID:   input.AssessmentID,
			Target:         cfg.Target,
			Iteration:      int(iteration),
			MaxIterations:  int(maxIterations),
			Findings:       SummarizeFindings(allFindings),
			CagesCompleted: cagesCompleted,
			Coverage:       coverage,
			TokenBudget:    cfg.TokenBudget,
			TimeElapsed:    elapsed,
			TimeLimit:      cfg.MaxDuration,
		}

		// Call LLM coordinator
		decision, err := planNextActions(ctx, state)
		if err != nil {
			return failResult(result, "coordinator planning (iteration %d): %v", iteration, err), nil
		}

		if decision.Done {
			break
		}

		// Spawn cages from coordinator decisions
		maxConcurrent := maxConcurrentForType(cfg, cage.TypeDiscovery)
		spawned, completedSummaries, err := spawnCoordinatorActions(ctx, input.AssessmentID, cfg, decision.Actions, maxConcurrent)
		if err != nil {
			return failResult(result, "spawning cages (iteration %d): %v", iteration, err), nil
		}
		result.TotalCages += spawned
		cagesCompleted = append(cagesCompleted, completedSummaries...)
		coverage = UpdateCoverage(coverage, decision.Actions)

		// Wait for cages to complete
		if err := workflow.Sleep(ctx, TimeoutWaitForCage); err != nil {
			return failResult(result, "waiting for cages (iteration %d): %v", iteration, err), nil
		}
	}

	// ===== Phase 3: Validation (deterministic, playbook-driven) =====

	if err := updateStatus(ctx, input.AssessmentID, StatusValidation); err != nil {
		return failResult(result, "updating status to validating: %v", err), nil
	}

	candidates, err := getCandidateFindings(ctx, input.AssessmentID)
	if err != nil {
		return failResult(result, "fetching candidate findings for validation: %v", err), nil
	}

	_, validatorCages, err := validateFindings(ctx, input.AssessmentID, candidates)
	if err != nil {
		return failResult(result, "validating findings: %v", err), nil
	}
	result.TotalCages += validatorCages

	// ===== Phase 4: Escalation =====

	validated, err := getValidatedFindings(ctx, input.AssessmentID)
	if err != nil {
		return failResult(result, "fetching validated findings for escalation: %v", err), nil
	}

	chainDepths := make(map[string]int32, len(validated))
	for i := range validated {
		chainDepths[validated[i].ID] = validated[i].ChainDepth
	}

	escalationCages := spawnEscalationCages(ctx, input.AssessmentID, cfg, validated, chainDepths, maxChainDepth)
	result.TotalCages += escalationCages

	// ===== Phase 5: Report generation + human review =====

	validated, err = getValidatedFindings(ctx, input.AssessmentID)
	if err != nil {
		return failResult(result, "fetching validated findings for report: %v", err), nil
	}
	result.Findings = int32(len(validated))

	if err := generateReport(ctx, input.AssessmentID, validated); err != nil {
		return failResult(result, "generating draft report: %v", err), nil
	}

	if err := updateStatus(ctx, input.AssessmentID, StatusPendingReview); err != nil {
		return failResult(result, "updating status to pending_review: %v", err), nil
	}

	decision, err := waitForReportReview(ctx)
	if err != nil {
		return failResult(result, "waiting for report review: %v", err), nil
	}

	switch decision.Decision {
	case intervention.ReviewApprove:
		if err := updateStatus(ctx, input.AssessmentID, StatusApproved); err != nil {
			return failResult(result, "updating status to approved: %v", err), nil
		}
		result.FinalStatus = StatusApproved

	case intervention.ReviewReject:
		if err := updateStatus(ctx, input.AssessmentID, StatusRejected); err != nil {
			return failResult(result, "updating status to rejected: %v", err), nil
		}
		result.FinalStatus = StatusRejected

	case intervention.ReviewRequestRetest:
		retestCages, retestErr := retestFindings(ctx, input.AssessmentID, cfg, decision.Adjustments)
		if retestErr != nil {
			return failResult(result, "retesting findings: %v", retestErr), nil
		}
		result.TotalCages += retestCages

		validated, err = getValidatedFindings(ctx, input.AssessmentID)
		if err != nil {
			return failResult(result, "fetching validated findings after retest: %v", err), nil
		}
		result.Findings = int32(len(validated))

		if err := generateReport(ctx, input.AssessmentID, validated); err != nil {
			return failResult(result, "generating final report after retest: %v", err), nil
		}
		if err := updateStatus(ctx, input.AssessmentID, StatusApproved); err != nil {
			return failResult(result, "updating status to approved after retest: %v", err), nil
		}
		result.FinalStatus = StatusApproved

	default:
		if err := updateStatus(ctx, input.AssessmentID, StatusRejected); err != nil {
			return failResult(result, "updating status to rejected after review timeout: %v", err), nil
		}
		result.FinalStatus = StatusRejected
	}

	return result, nil
}

// --- Activity helpers ---

func assessmentActivityOptions(timeout time.Duration) workflow.ActivityOptions {
	return workflow.ActivityOptions{
		StartToCloseTimeout: timeout,
		RetryPolicy: &temporal.RetryPolicy{
			MaximumAttempts: 3,
		},
	}
}

func withActivityTimeout(ctx workflow.Context, timeout time.Duration) workflow.Context {
	return workflow.WithActivityOptions(ctx, assessmentActivityOptions(timeout))
}

func updateStatus(ctx workflow.Context, assessmentID string, status Status) error {
	actCtx := withActivityTimeout(ctx, TimeoutUpdateStatus)
	return workflow.ExecuteActivity(actCtx, "UpdateAssessmentStatus", assessmentID, status).Get(ctx, nil)
}

func createDiscoveryCage(ctx workflow.Context, assessmentID string, cfg Config) (string, error) {
	actCtx := withActivityTimeout(ctx, TimeoutCreateCage)
	cageCfg := cage.Config{
		AssessmentID: assessmentID,
		Type:         cage.TypeDiscovery,
		Scope:        cfg.Target,
	}
	if tc, ok := cfg.CageDefaults[cage.TypeDiscovery]; ok {
		cageCfg.Resources = tc.Resources
	}

	var cageID string
	err := workflow.ExecuteActivity(actCtx, "CreateDiscoveryCage", assessmentID, cageCfg).Get(ctx, &cageID)
	return cageID, err
}

func planNextActions(ctx workflow.Context, state CoordinatorState) (CoordinatorDecision, error) {
	actCtx := withActivityTimeout(ctx, TimeoutPlanNextActions)
	var decision CoordinatorDecision
	err := workflow.ExecuteActivity(actCtx, "PlanNextActions", state).Get(ctx, &decision)
	return decision, err
}

func getAllFindings(ctx workflow.Context, assessmentID string) ([]findings.Finding, error) {
	actCtx := withActivityTimeout(ctx, TimeoutGetFindings)
	var result []findings.Finding
	err := workflow.ExecuteActivity(actCtx, "GetCandidateFindings", assessmentID).Get(ctx, &result)
	return result, err
}

func getCandidateFindings(ctx workflow.Context, assessmentID string) ([]findings.Finding, error) {
	actCtx := withActivityTimeout(ctx, TimeoutGetFindings)
	var result []findings.Finding
	err := workflow.ExecuteActivity(actCtx, "GetCandidateFindings", assessmentID).Get(ctx, &result)
	return result, err
}

func getValidatedFindings(ctx workflow.Context, assessmentID string) ([]findings.Finding, error) {
	actCtx := withActivityTimeout(ctx, TimeoutGetFindings)
	var result []findings.Finding
	err := workflow.ExecuteActivity(actCtx, "GetValidatedFindings", assessmentID).Get(ctx, &result)
	return result, err
}

func generateReport(ctx workflow.Context, assessmentID string, validated []findings.Finding) error {
	actCtx := withActivityTimeout(ctx, TimeoutGenerateReport)
	return workflow.ExecuteActivity(actCtx, "GenerateReport", assessmentID, validated).Get(ctx, nil)
}

func maxConcurrentForType(cfg Config, cageType cage.Type) int32 {
	if tc, ok := cfg.CageDefaults[cageType]; ok && tc.MaxConcurrent > 0 {
		return tc.MaxConcurrent
	}
	return DefaultMaxConcurrent
}

// spawnCoordinatorActions creates cages from coordinator decisions.
func spawnCoordinatorActions(
	ctx workflow.Context,
	assessmentID string,
	cfg Config,
	actions []CoordinatorAction,
	maxConcurrent int32,
) (int32, []CageSummary, error) {
	var spawned int32
	var summaries []CageSummary

	batchSize := int(maxConcurrent)

	for i := 0; i < len(actions); i += batchSize {
		end := i + batchSize
		if end > len(actions) {
			end = len(actions)
		}
		batch := actions[i:end]

		futures := make([]workflow.Future, 0, len(batch))
		for _, action := range batch {
			actCtx := withActivityTimeout(ctx, TimeoutCreateCage)

			cageType := cage.TypeDiscovery
			switch action.Type {
			case "validator":
				cageType = cage.TypeValidator
			case "escalation":
				cageType = cage.TypeEscalation
			}

			cageCfg := cage.Config{
				AssessmentID:    assessmentID,
				Type:            cageType,
				Scope:           action.Scope,
				ParentFindingID: action.FindingID,
				InputContext:     []byte(action.Objective),
			}
			if tc, ok := cfg.CageDefaults[cageType]; ok {
				cageCfg.Resources = tc.Resources
			}

			var activityName string
			switch action.Type {
			case "discovery":
				activityName = "CreateDiscoveryCage"
			case "validator":
				activityName = "CreateValidatorCage"
			case "escalation":
				activityName = "CreateEscalationCage"
			default:
				activityName = "CreateDiscoveryCage"
			}

			f := workflow.ExecuteActivity(actCtx, activityName, assessmentID, cageCfg)
			futures = append(futures, f)
		}

		for j, f := range futures {
			var cageID string
			if err := f.Get(ctx, &cageID); err != nil {
				return spawned, summaries, fmt.Errorf("creating cage for action %q: %w", batch[j].Objective, err)
			}
			spawned++
			summaries = append(summaries, CageSummary{
				CageID:    cageID,
				CageType:  batch[j].Type,
				VulnClass: batch[j].VulnClass,
				Objective: batch[j].Objective,
			})
		}
	}

	return spawned, summaries, nil
}

func validateFindings(
	ctx workflow.Context,
	assessmentID string,
	candidates []findings.Finding,
) (int32, int32, error) {
	var validatedCount int32
	var cagesSpawned int32

	for _, f := range candidates {
		if f.Status != findings.StatusCandidate {
			continue
		}

		actCtx := withActivityTimeout(ctx, TimeoutCreateCage)
		var cageID string
		err := workflow.ExecuteActivity(actCtx, "CreateValidatorCage", assessmentID, f, (*Playbook)(nil)).Get(ctx, &cageID)
		if err != nil {
			return validatedCount, cagesSpawned, fmt.Errorf("creating validator cage for finding %s: %w", f.ID, err)
		}
		cagesSpawned++

		if err := workflow.Sleep(ctx, TimeoutWaitForCage); err != nil {
			return validatedCount, cagesSpawned, fmt.Errorf("waiting for validator cage: %w", err)
		}

		actCtx = withActivityTimeout(ctx, TimeoutGetFindings)
		var updated []findings.Finding
		if err := workflow.ExecuteActivity(actCtx, "GetCandidateFindings", assessmentID).Get(ctx, &updated); err != nil {
			return validatedCount, cagesSpawned, fmt.Errorf("checking validation result for finding %s: %w", f.ID, err)
		}

		for _, u := range updated {
			if u.ID == f.ID && u.Status == findings.StatusValidated {
				validatedCount++
				break
			}
		}
	}

	return validatedCount, cagesSpawned, nil
}

func spawnEscalationCages(
	ctx workflow.Context,
	assessmentID string,
	cfg Config,
	validated []findings.Finding,
	chainDepths map[string]int32,
	maxChainDepth int32,
) int32 {
	var spawned int32

	for _, f := range validated {
		if f.Severity != findings.SeverityHigh && f.Severity != findings.SeverityCritical {
			continue
		}

		depth := chainDepths[f.ID]
		if depth >= maxChainDepth {
			continue
		}

		actCtx := withActivityTimeout(ctx, TimeoutCreateCage)
		escalationCfg := cage.Config{
			AssessmentID:    assessmentID,
			Type:            cage.TypeEscalation,
			Scope:           cfg.Target,
			ParentFindingID: f.ID,
		}
		if tc, ok := cfg.CageDefaults[cage.TypeEscalation]; ok {
			escalationCfg.Resources = tc.Resources
		}

		var cageID string
		err := workflow.ExecuteActivity(actCtx, "CreateEscalationCage", assessmentID, f, escalationCfg).Get(ctx, &cageID)
		if err != nil {
			continue
		}
		spawned++
		chainDepths[f.ID] = depth + 1
	}

	return spawned
}

func waitForReportReview(ctx workflow.Context) (*intervention.ReportReviewSignal, error) {
	signalCh := workflow.GetSignalChannel(ctx, intervention.SignalReportReview)
	timer := workflow.NewTimer(ctx, TimeoutReviewDeadline)

	sel := workflow.NewSelector(ctx)
	var signal intervention.ReportReviewSignal
	var timedOut bool

	sel.AddReceive(signalCh, func(ch workflow.ReceiveChannel, more bool) {
		ch.Receive(ctx, &signal)
	})
	sel.AddFuture(timer, func(f workflow.Future) {
		_ = f.Get(ctx, nil)
		timedOut = true
	})
	sel.Select(ctx)

	if timedOut {
		return &intervention.ReportReviewSignal{
			Decision:  intervention.ReviewReject,
			Rationale: "review deadline exceeded",
		}, nil
	}

	return &signal, nil
}

func retestFindings(
	ctx workflow.Context,
	assessmentID string,
	cfg Config,
	adjustments []intervention.FindingAdjustment,
) (int32, error) {
	var cages int32

	for _, adj := range adjustments {
		actCtx := withActivityTimeout(ctx, TimeoutCreateCage)
		f := findings.Finding{
			ID:           adj.FindingID,
			AssessmentID: assessmentID,
		}
		var cageID string
		err := workflow.ExecuteActivity(actCtx, "CreateValidatorCage", assessmentID, f, (*Playbook)(nil)).Get(ctx, &cageID)
		if err != nil {
			return cages, fmt.Errorf("creating retest cage for finding %s: %w", adj.FindingID, err)
		}
		cages++
	}

	if cages > 0 {
		if err := workflow.Sleep(ctx, TimeoutWaitForCage); err != nil {
			return cages, fmt.Errorf("waiting for retest cages: %w", err)
		}
	}

	return cages, nil
}

func failResult(result AssessmentWorkflowResult, format string, args ...interface{}) AssessmentWorkflowResult {
	result.FinalStatus = StatusRejected
	result.Error = fmt.Sprintf(format, args...)
	return result
}
