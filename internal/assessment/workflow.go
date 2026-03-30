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
	TimeoutReviewDeadline  = 24 * time.Hour
	TimeoutWaitForCage     = 10 * time.Minute
	DefaultMaxConcurrent   = int32(10)
	DefaultMaxChainDepth   = int32(3)
)

type AssessmentWorkflowInput struct {
	AssessmentID string
	Config       Config
}

type AssessmentWorkflowResult struct {
	AssessmentID string
	FinalStatus  Status
	TotalCages   int32
	Findings     int32
	Error        string
}

func AssessmentWorkflow(ctx workflow.Context, input AssessmentWorkflowInput) (AssessmentWorkflowResult, error) {
	result := AssessmentWorkflowResult{AssessmentID: input.AssessmentID}
	cfg := input.Config

	maxChainDepth := cfg.MaxChainDepth
	if maxChainDepth <= 0 {
		maxChainDepth = DefaultMaxChainDepth
	}

	// --- Surface mapping phase ---

	if err := updateStatus(ctx, input.AssessmentID, StatusMapping); err != nil {
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

	candidates, err := getCandidateFindings(ctx, input.AssessmentID)
	if err != nil {
		return failResult(result, "fetching candidate findings after surface mapping: %v", err), nil
	}

	// --- Task matrix generation (deterministic, no I/O) ---

	matrix := buildTaskMatrix(candidates)

	// --- Testing phase ---

	if err := updateStatus(ctx, input.AssessmentID, StatusTesting); err != nil {
		return failResult(result, "updating status to testing: %v", err), nil
	}

	maxConcurrent := maxConcurrentForType(cfg, cage.TypeDiscovery)
	cagesSpawned, err := spawnDiscoveryCages(ctx, input.AssessmentID, cfg, matrix, maxConcurrent)
	if err != nil {
		return failResult(result, "spawning discovery cages: %v", err), nil
	}
	result.TotalCages += cagesSpawned

	if err := workflow.Sleep(ctx, TimeoutWaitForCage); err != nil {
		return failResult(result, "waiting for discovery cages: %v", err), nil
	}

	// --- Validation phase ---

	if err := updateStatus(ctx, input.AssessmentID, StatusValidating); err != nil {
		return failResult(result, "updating status to validating: %v", err), nil
	}

	candidates, err = getCandidateFindings(ctx, input.AssessmentID)
	if err != nil {
		return failResult(result, "fetching candidate findings for validation: %v", err), nil
	}

	validatedCount, validatorCages, err := validateFindings(ctx, input.AssessmentID, candidates)
	if err != nil {
		return failResult(result, "validating findings: %v", err), nil
	}
	result.TotalCages += validatorCages

	// --- Escalation phase ---

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

	// --- Report generation phase ---

	validated, err = getValidatedFindings(ctx, input.AssessmentID)
	if err != nil {
		return failResult(result, "fetching validated findings for report: %v", err), nil
	}
	result.Findings = int32(len(validated))
	_ = validatedCount

	if err := generateReport(ctx, input.AssessmentID, validated); err != nil {
		return failResult(result, "generating draft report: %v", err), nil
	}

	if err := updateStatus(ctx, input.AssessmentID, StatusPendingReview); err != nil {
		return failResult(result, "updating status to pending_review: %v", err), nil
	}

	// --- Human review phase ---

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
		// Retest requested findings then re-generate report and auto-approve.
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
		Scope:        cfg.Scope,
	}
	if tc, ok := cfg.CageDefaults[cage.TypeDiscovery]; ok {
		cageCfg.Resources = tc.Resources
	}

	var cageID string
	err := workflow.ExecuteActivity(actCtx, "CreateDiscoveryCage", assessmentID, cageCfg).Get(ctx, &cageID)
	if err != nil {
		return "", err
	}
	return cageID, nil
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

func buildTaskMatrix(candidates []findings.Finding) []TaskMatrixEntry {
	var matrix []TaskMatrixEntry
	for _, f := range candidates {
		matrix = append(matrix, TaskMatrixEntry{
			Endpoint:  f.Endpoint,
			VulnClass: f.VulnClass,
		})
	}
	return matrix
}

func maxConcurrentForType(cfg Config, cageType cage.Type) int32 {
	if tc, ok := cfg.CageDefaults[cageType]; ok && tc.MaxConcurrent > 0 {
		return tc.MaxConcurrent
	}
	return DefaultMaxConcurrent
}

func spawnDiscoveryCages(
	ctx workflow.Context,
	assessmentID string,
	cfg Config,
	matrix []TaskMatrixEntry,
	maxConcurrent int32,
) (int32, error) {
	if len(matrix) == 0 {
		return 0, nil
	}

	var spawned int32
	batchSize := int(maxConcurrent)

	for i := 0; i < len(matrix); i += batchSize {
		end := i + batchSize
		if end > len(matrix) {
			end = len(matrix)
		}
		batch := matrix[i:end]

		futures := make([]workflow.Future, 0, len(batch))
		for _, entry := range batch {
			actCtx := withActivityTimeout(ctx, TimeoutCreateCage)
			cageCfg := cage.Config{
				AssessmentID: assessmentID,
				Type:         cage.TypeDiscovery,
				Scope:        cage.Scope{Hosts: []string{entry.Endpoint}},
			}
			if tc, ok := cfg.CageDefaults[cage.TypeDiscovery]; ok {
				cageCfg.Resources = tc.Resources
			}
			f := workflow.ExecuteActivity(actCtx, "CreateDiscoveryCage", assessmentID, cageCfg)
			futures = append(futures, f)
		}

		for _, f := range futures {
			var cageID string
			if err := f.Get(ctx, &cageID); err != nil {
				return spawned, fmt.Errorf("creating discovery cage: %w", err)
			}
			spawned++
		}
	}

	return spawned, nil
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
			Scope:           cfg.Scope,
			ParentFindingID: f.ID,
		}
		if tc, ok := cfg.CageDefaults[cage.TypeEscalation]; ok {
			escalationCfg.Resources = tc.Resources
		}

		var cageID string
		err := workflow.ExecuteActivity(actCtx, "CreateEscalationCage", assessmentID, f, escalationCfg).Get(ctx, &cageID)
		if err != nil {
			// Best-effort: escalation failure should not abort the assessment.
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
		_ = f.Get(ctx, nil) // best-effort, nothing actionable if timer errors
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
