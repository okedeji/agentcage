package cage

import (
	"errors"
	"fmt"
	"time"

	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/workflow"

	"github.com/okedeji/agentcage/internal/identity"
	"github.com/okedeji/agentcage/internal/intervention"
)

// WorkflowName is the registered name of CageWorkflow in the Temporal
// worker. Pinned explicitly so a Go-side rename of the function does not
// silently break in-flight workflows on the next history replay.
const WorkflowName = "CageWorkflow"

type CageWorkflowInput struct {
	Config      Config
	CageID      string
	LLMEndpoint string
	NATSAddr    string
	Timeouts    Timeouts
}

type CageWorkflowResult struct {
	CageID     string
	FinalState State
	StopReason StopReason
	Error      string
}

func CageWorkflow(ctx workflow.Context, input CageWorkflowInput) (CageWorkflowResult, error) {
	cfg := input.Config
	t := input.Timeouts
	result := CageWorkflowResult{CageID: input.CageID}

	var svid identity.SVID
	var token identity.VaultToken
	var vmHandle VMHandle
	var setupReachedVM bool
	var setupReachedPolicy bool

	if err := execActivity(withTimeout(ctx, t.ValidateScope), "ValidateCageConfig", cfg); err != nil {
		return failResult(result, "validating cage config: %v", err), nil
	}

	if err := workflow.ExecuteActivity(
		withTimeout(ctx, t.IssueIdentity),
		"IssueIdentity", input.CageID, cfg.TimeLimits.MaxDuration,
	).Get(ctx, &svid); err != nil {
		return failResult(result, "issuing identity: %v", err), nil
	}

	if err := workflow.ExecuteActivity(
		withTimeout(ctx, t.FetchSecrets),
		"FetchSecrets", &svid, cfg.AssessmentID,
	).Get(ctx, &token); err != nil {
		cleanupIdentity(ctx, t, svid.ID, nil)
		return failResult(result, "fetching secrets: %v", err), nil
	}

	env := Env{
		CageID:       input.CageID,
		AssessmentID: cfg.AssessmentID,
		CageType:     cfg.Type.String(),
		Objective:    string(cfg.InputContext),
		VulnClass:    cfg.VulnClass,
		LLMEndpoint:  input.LLMEndpoint,
		NATSAddr:     input.NATSAddr,
		ScopeHosts:   cfg.Scope.Hosts,
		ScopePorts:   cfg.Scope.Ports,
		ScopePaths:   cfg.Scope.Paths,
		SkipPaths:    cfg.SkipPaths,
		ProxyMode:    cfg.ProxyConfig.Mode.String(),
		Guidance:     cfg.Guidance,
	}
	if cfg.LLM != nil {
		env.TokenBudget = cfg.LLM.TokenBudget
	}
	var rootfsPath string
	if err := workflow.ExecuteActivity(
		withHeartbeat(ctx, t.ProvisionVM, t.HeartbeatProvisionVM),
		"AssembleRootfs", input.CageID, cfg.BundleRef, env,
	).Get(ctx, &rootfsPath); err != nil {
		cleanupIdentity(ctx, t, svid.ID, &token)
		return failResult(result, "assembling rootfs: %v", err), nil
	}

	if err := workflow.ExecuteActivity(
		withHeartbeat(ctx, t.ProvisionVM, t.HeartbeatProvisionVM),
		"ProvisionVM", VMConfig{
			CageID:     input.CageID,
			VCPUs:      cfg.Resources.VCPUs,
			MemoryMB:   cfg.Resources.MemoryMB,
			RootfsPath: rootfsPath,
		},
	).Get(ctx, &vmHandle); err != nil {
		cleanupIdentity(ctx, t, svid.ID, &token)
		return failResult(result, "provisioning VM: %v", err), nil
	}
	setupReachedVM = true

	extras := []string{input.LLMEndpoint, input.NATSAddr}
	if err := execActivity(
		withTimeout(ctx, t.ApplyPolicy),
		"ApplyNetworkPolicy", input.CageID, cfg.Scope, extras,
	); err != nil {
		cleanupPartial(ctx, t, svid.ID, &token, vmHandle.ID)
		return failResult(result, "applying network policy: %v", err), nil
	}
	setupReachedPolicy = true

	if cfg.ProxyConfig.Mode != ProxyModeDisabled {
		if err := execActivity(
			withTimeout(ctx, t.StartAgent),
			"StartPayloadProxy", &vmHandle, "",
		); err != nil {
			cleanupPartial(ctx, t, svid.ID, &token, vmHandle.ID)
			return failResult(result, "starting payload proxy: %v", err), nil
		}
	}

	if err := execActivity(
		withTimeout(ctx, t.StartAgent),
		"StartAgent", &vmHandle, cfg,
	); err != nil {
		cleanupPartial(ctx, t, svid.ID, &token, vmHandle.ID)
		return failResult(result, "starting agent: %v", err), nil
	}

	// --- Monitor phase ---

	stopReason := runMonitorWithSignals(ctx, cfg, input.CageID, t)

	// --- Teardown phase ---
	// All steps execute regardless of individual failures. An orphaned VM
	// running exploit code with valid credentials is the worst outcome.

	var teardownErrs []error

	if tErr := execActivity(withTimeout(ctx, t.ExportAuditLog), "ExportAuditLog", input.CageID); tErr != nil {
		teardownErrs = append(teardownErrs, fmt.Errorf("exporting audit log: %w", tErr))
	}

	if setupReachedVM {
		if tErr := execActivity(withTimeout(ctx, t.TeardownVM), "TeardownVM", vmHandle.ID); tErr != nil {
			teardownErrs = append(teardownErrs, fmt.Errorf("tearing down VM: %w", tErr))
		}
	}

	if tErr := execActivity(withTimeout(ctx, t.RevokeSVID), "RevokeSVID", svid.ID); tErr != nil {
		teardownErrs = append(teardownErrs, fmt.Errorf("revoking SVID: %w", tErr))
	}

	if tErr := execActivity(withTimeout(ctx, t.RevokeVaultToken), "RevokeVaultToken", &token); tErr != nil {
		teardownErrs = append(teardownErrs, fmt.Errorf("revoking Vault token: %w", tErr))
	}

	if setupReachedPolicy {
		if tErr := execActivity(withTimeout(ctx, t.ApplyPolicy), "RemoveNetworkPolicy", input.CageID); tErr != nil {
			teardownErrs = append(teardownErrs, fmt.Errorf("removing network policy: %w", tErr))
		}
	}

	if tErr := execActivity(withTimeout(ctx, t.VerifyCleanup), "VerifyCleanup", input.CageID); tErr != nil {
		teardownErrs = append(teardownErrs, fmt.Errorf("verifying cleanup: %w", tErr))
	}

	if stopReason.RequiresRCA() || result.Error != "" {
		reason := stopReason.String()
		if result.Error != "" {
			reason = result.Error
		}
		// Best-effort: RCA failure is not a security concern
		_ = execActivity(withTimeout(ctx, t.ExportAuditLog), "EmitRCA", input.CageID, cfg.AssessmentID, reason)
	}

	// Best-effort observability
	_ = execActivity(withTimeout(ctx, t.ExportAuditLog), "RecordRunMetrics", input.CageID, cfg.AssessmentID)
	_ = execActivity(withTimeout(ctx, t.ExportAuditLog), "RecordCostMetrics", input.CageID, cfg.AssessmentID)

	switch stopReason {
	case StopReasonCompleted:
		result.FinalState = StateCompleted
	case StopReasonTimeout, StopReasonBudgetExhausted:
		result.FinalState = StateCompleted
	default:
		result.FinalState = StateFailed
	}
	result.StopReason = stopReason

	if len(teardownErrs) > 0 {
		result.Error = fmt.Sprintf("teardown errors: %v", errors.Join(teardownErrs...))
		result.FinalState = StateFailed
	}

	return result, nil
}

func runMonitorWithSignals(ctx workflow.Context, cfg Config, cageID string, t Timeouts) StopReason {
	monitorTimeout := cfg.TimeLimits.MaxDuration + 60*time.Second
	monitorCtx := withHeartbeat(ctx, monitorTimeout, t.HeartbeatMonitorCage)
	monitorFuture := workflow.ExecuteActivity(monitorCtx, "MonitorCage", cageID, cfg)

	signalCh := workflow.GetSignalChannel(ctx, intervention.SignalIntervention)
	sel := workflow.NewSelector(ctx)

	var stopReason StopReason
	var monitorErr error
	var monitorDone bool

	sel.AddFuture(monitorFuture, func(f workflow.Future) {
		monitorErr = f.Get(ctx, &stopReason)
		monitorDone = true
	})

	sel.AddReceive(signalCh, func(ch workflow.ReceiveChannel, more bool) {
		var signal intervention.InterventionSignal
		ch.Receive(ctx, &signal)

		switch signal.Action {
		case intervention.ActionKill:
			stopReason = StopReasonTripwire
			monitorDone = true
		case intervention.ActionResume, intervention.ActionAdjustAndResume:
			// MonitorCage activity handles the actual pause/resume mechanics.
			// The signal is consumed so the selector can re-enter the loop.
		}
	})

	for !monitorDone {
		sel.Select(ctx)
	}

	if monitorErr != nil && stopReason == 0 {
		stopReason = StopReasonError
	}

	return stopReason
}

func withTimeout(ctx workflow.Context, timeout time.Duration) workflow.Context {
	return workflow.WithActivityOptions(ctx, workflow.ActivityOptions{
		StartToCloseTimeout: timeout,
		RetryPolicy: &temporal.RetryPolicy{
			MaximumAttempts: 3,
		},
	})
}

func withHeartbeat(ctx workflow.Context, timeout, heartbeat time.Duration) workflow.Context {
	return workflow.WithActivityOptions(ctx, workflow.ActivityOptions{
		StartToCloseTimeout: timeout,
		HeartbeatTimeout:    heartbeat,
		RetryPolicy: &temporal.RetryPolicy{
			MaximumAttempts: 3,
		},
	})
}

func execActivity(ctx workflow.Context, name string, args ...interface{}) error {
	return workflow.ExecuteActivity(ctx, name, args...).Get(ctx, nil)
}

func failResult(result CageWorkflowResult, format string, args ...interface{}) CageWorkflowResult {
	result.FinalState = StateFailed
	result.Error = fmt.Sprintf(format, args...)
	return result
}

func cleanupIdentity(ctx workflow.Context, t Timeouts, svidID string, token *identity.VaultToken) {
	_ = execActivity(withTimeout(ctx, t.RevokeSVID), "RevokeSVID", svidID)
	if token != nil {
		_ = execActivity(withTimeout(ctx, t.RevokeVaultToken), "RevokeVaultToken", token)
	}
}

func cleanupPartial(ctx workflow.Context, t Timeouts, svidID string, token *identity.VaultToken, vmID string) {
	_ = execActivity(withTimeout(ctx, t.RevokeSVID), "RevokeSVID", svidID)
	_ = execActivity(withTimeout(ctx, t.RevokeVaultToken), "RevokeVaultToken", token)
	_ = execActivity(withTimeout(ctx, t.TeardownVM), "TeardownVM", vmID)
}
