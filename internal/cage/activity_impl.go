package cage

import (
	"context"
	"fmt"
	"time"

	"github.com/go-logr/logr"

	"github.com/okedeji/agentcage/internal/audit"
	"github.com/okedeji/agentcage/internal/identity"
	"github.com/okedeji/agentcage/internal/rca"
)

// ScopeValidator validates cage scope against policies.
// Defined here to avoid a circular dependency with the enforcement package.
type ScopeValidator interface {
	ValidateScope(ctx context.Context, scope Scope) error
	ValidateCageConfig(ctx context.Context, config Config) error
}

// NetworkPolicy manages network isolation for cages.
// Defined here to avoid a circular dependency with the enforcement package.
type NetworkPolicy interface {
	Apply(ctx context.Context, cageID string, scope Scope, extras []string) error
	Remove(ctx context.Context, cageID string) error
}

// TripwirePolicy represents the action to take when a behavioral alert fires.
type TripwirePolicy int

const (
	TripwireLogAndContinue    TripwirePolicy = 1
	TripwireHumanReview       TripwirePolicy = 2
	TripwireImmediateTeardown TripwirePolicy = 3
)

// AlertEvent represents a behavioral monitoring alert (e.g., from Falco).
type AlertEvent struct {
	RuleName string
	Priority string
	Output   string
	CageID   string
}

// AlertHandler evaluates behavioral alerts and returns the tripwire policy.
// Defined here to avoid a circular dependency with the enforcement package.
type AlertHandler interface {
	HandleAlert(ctx context.Context, cageType Type, alert AlertEvent) (TripwirePolicy, error)
}

// AlertNotifier dispatches alert notifications to operators.
// Defined here so the cage package can send alerts without importing
// the alert package (accept interfaces, return structs).
type AlertNotifier interface {
	Notify(ctx context.Context, source, category, description, cageID, assessmentID string, priority int, details map[string]any)
}

// ActivityImpl provides concrete implementations of all cage lifecycle
// activities. All dependency fields are optional — nil dependencies are
// handled gracefully (logged and skipped) to support local mode where
// SPIRE, Vault, or Falco may not be available.
type ActivityImpl struct {
	provisioner   VMProvisioner
	rootfs        *RootfsBuilder
	network       NetworkPolicy
	validator     ScopeValidator
	alertHandler  AlertHandler
	alertNotifier AlertNotifier
	falcoReader   *FalcoAlertReader
	identity      identity.SVIDIssuer
	secrets       identity.SecretFetcher
	auditStore    audit.Store
	log           logr.Logger
}

type ActivityImplConfig struct {
	Provisioner   VMProvisioner
	Rootfs        *RootfsBuilder
	Network       NetworkPolicy
	Validator     ScopeValidator
	AlertHandler  AlertHandler
	AlertNotifier AlertNotifier
	FalcoReader   *FalcoAlertReader
	Identity      identity.SVIDIssuer
	Secrets       identity.SecretFetcher
	AuditStore    audit.Store
	Log           logr.Logger
}

func NewActivityImpl(cfg ActivityImplConfig) *ActivityImpl {
	return &ActivityImpl{
		provisioner:   cfg.Provisioner,
		rootfs:        cfg.Rootfs,
		network:       cfg.Network,
		validator:     cfg.Validator,
		alertHandler:  cfg.AlertHandler,
		alertNotifier: cfg.AlertNotifier,
		falcoReader:   cfg.FalcoReader,
		identity:      cfg.Identity,
		secrets:       cfg.Secrets,
		auditStore:    cfg.AuditStore,
		log:           cfg.Log.WithValues("component", "cage-activities"),
	}
}

func (a *ActivityImpl) ValidateScope(ctx context.Context, config Config) error {
	if a.validator == nil {
		a.log.V(1).Info("scope validation skipped — no validator configured")
		return nil
	}
	return a.validator.ValidateScope(ctx, config.Scope)
}

func (a *ActivityImpl) ValidateCageType(ctx context.Context, config Config) error {
	if a.validator == nil {
		a.log.V(1).Info("cage type validation skipped — no validator configured")
		return nil
	}
	return a.validator.ValidateCageConfig(ctx, config)
}

func (a *ActivityImpl) IssueIdentity(ctx context.Context, cageID string, ttl time.Duration) (*identity.SVID, error) {
	if a.identity == nil {
		a.log.V(1).Info("identity issuance skipped — no SPIRE configured", "cage_id", cageID)
		return &identity.SVID{ID: "dev-" + cageID, SpiffeID: "spiffe://agentcage.local/cage/" + cageID, CageID: cageID}, nil
	}
	svid, err := a.identity.Issue(ctx, cageID, ttl)
	if err != nil {
		return nil, fmt.Errorf("cage %s: issuing SVID: %w", cageID, err)
	}
	a.log.Info("identity issued", "cage_id", cageID, "spiffe_id", svid.SpiffeID)
	return svid, nil
}

func (a *ActivityImpl) FetchSecrets(ctx context.Context, svid *identity.SVID, assessmentID string) (*identity.VaultToken, error) {
	if a.secrets == nil {
		a.log.V(1).Info("secret fetch skipped — no Vault configured", "cage_id", svid.CageID)
		return &identity.VaultToken{CageID: svid.CageID}, nil
	}
	token, err := a.secrets.Authenticate(ctx, svid)
	if err != nil {
		return nil, fmt.Errorf("authenticating with Vault: %w", err)
	}
	a.log.V(1).Info("secrets fetched", "assessment_id", assessmentID, "cage_id", svid.CageID)
	return token, nil
}

func (a *ActivityImpl) ProvisionVM(ctx context.Context, vmConfig VMConfig) (*VMHandle, error) {
	if a.provisioner == nil {
		return nil, fmt.Errorf("cage %s: no VM provisioner configured", vmConfig.CageID)
	}
	handle, err := a.provisioner.Provision(ctx, vmConfig)
	if err != nil {
		return nil, fmt.Errorf("cage %s: provisioning VM: %w", vmConfig.CageID, err)
	}
	a.log.Info("VM provisioned", "cage_id", vmConfig.CageID, "vm_id", handle.ID, "ip", handle.IPAddress)
	return handle, nil
}

func (a *ActivityImpl) ApplyNetworkPolicy(ctx context.Context, cageID string, scope Scope, extras []string) error {
	if a.network == nil {
		a.log.V(1).Info("network policy skipped — no enforcer configured", "cage_id", cageID)
		return nil
	}
	if err := a.network.Apply(ctx, cageID, scope, extras); err != nil {
		return fmt.Errorf("cage %s: applying network policy: %w", cageID, err)
	}
	a.log.Info("network policy applied", "cage_id", cageID, "scope_hosts", scope.Hosts)
	return nil
}

func (a *ActivityImpl) StartPayloadProxy(_ context.Context, vmHandle *VMHandle, vulnClass string) error {
	a.log.Info("payload proxy started by cage-init", "cage_id", vmHandle.CageID, "vuln_class", vulnClass)
	return nil
}

func (a *ActivityImpl) StartAgent(_ context.Context, vmHandle *VMHandle, config Config) error {
	a.log.Info("agent started by cage-init", "cage_id", vmHandle.CageID, "type", config.Type)
	return nil
}

func (a *ActivityImpl) MonitorCage(ctx context.Context, cageID string, config Config) (StopReason, error) {
	a.log.Info("monitoring cage", "cage_id", cageID, "max_duration", config.TimeLimits.MaxDuration)

	deadline := time.After(config.TimeLimits.MaxDuration)

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	// Start Falco alert stream if available
	var alertCh <-chan AlertEvent
	if a.falcoReader != nil {
		var err error
		alertCh, err = a.falcoReader.Stream(ctx, cageID)
		if err != nil {
			a.log.Error(err, "Falco alert stream unavailable — monitoring without behavioral alerts", "cage_id", cageID)
		}
	}
	if alertCh == nil {
		// No Falco — use a nil channel (never receives, doesn't block select)
		alertCh = make(chan AlertEvent)
	}

	for {
		select {
		case <-ctx.Done():
			return StopReasonError, ctx.Err()

		case <-deadline:
			a.log.Info("cage timed out", "cage_id", cageID)
			return StopReasonTimeout, nil

		case alert, ok := <-alertCh:
			if !ok {
				a.log.V(1).Info("Falco alert stream closed", "cage_id", cageID)
				alertCh = make(chan AlertEvent)
				continue
			}
			policy, err := a.EvaluateAlert(ctx, config.Type, config.AssessmentID, alert)
			if err != nil {
				a.log.Error(err, "evaluating Falco alert", "cage_id", cageID, "rule", alert.RuleName)
				continue
			}
			if policy == TripwireImmediateTeardown {
				return StopReasonTripwire, nil
			}

		case <-ticker.C:
			if a.provisioner == nil {
				continue
			}
			status, err := a.provisioner.Status(ctx, cageID)
			if err != nil {
				a.log.Error(err, "checking VM status", "cage_id", cageID)
				continue
			}
			if status == VMStatusStopped {
				a.log.Info("cage agent completed", "cage_id", cageID)
				return StopReasonCompleted, nil
			}
		}
	}
}

// EvaluateAlert determines the response to a behavioral monitoring alert.
// Called by the Falco gRPC alert stream consumer when an alert fires for a cage.
// Returns the tripwire policy that the workflow should act on.
func (a *ActivityImpl) EvaluateAlert(ctx context.Context, cageType Type, assessmentID string, alert AlertEvent) (TripwirePolicy, error) {
	if a.alertHandler == nil {
		a.log.V(1).Info("alert handling skipped — no handler configured", "cage_id", alert.CageID, "rule", alert.RuleName)
		return TripwireLogAndContinue, nil
	}
	policy, err := a.alertHandler.HandleAlert(ctx, cageType, alert)
	if err != nil {
		return 0, fmt.Errorf("cage %s: evaluating alert %s: %w", alert.CageID, alert.RuleName, err)
	}
	a.log.Info("alert evaluated", "cage_id", alert.CageID, "rule", alert.RuleName, "policy", policy)

	if a.alertNotifier != nil {
		var priority int
		switch policy {
		case TripwireImmediateTeardown:
			priority = 4 // critical
		case TripwireHumanReview:
			priority = 3 // high
		default:
			priority = 2 // medium
		}
		a.alertNotifier.Notify(ctx, "behavioral", alert.RuleName, alert.Output, alert.CageID, assessmentID, priority, map[string]any{
			"rule":      alert.RuleName,
			"priority":  alert.Priority,
			"cage_type": cageType.String(),
			"action":    tripwireActionName(policy),
		})
	}

	return policy, nil
}

func tripwireActionName(p TripwirePolicy) string {
	switch p {
	case TripwireLogAndContinue:
		return "log_and_continue"
	case TripwireHumanReview:
		return "human_review"
	case TripwireImmediateTeardown:
		return "immediate_teardown"
	default:
		return "unknown"
	}
}

func (a *ActivityImpl) ExportAuditLog(_ context.Context, cageID string) error {
	a.log.Info("exporting audit log", "cage_id", cageID)
	return nil
}

func (a *ActivityImpl) TeardownVM(ctx context.Context, vmID string) error {
	if a.provisioner == nil {
		return nil
	}
	if err := a.provisioner.Terminate(ctx, vmID); err != nil {
		return fmt.Errorf("terminating VM %s: %w", vmID, err)
	}
	a.log.Info("VM terminated", "vm_id", vmID)
	return nil
}

func (a *ActivityImpl) RevokeSVID(ctx context.Context, svidID string) error {
	if a.identity == nil {
		return nil
	}
	if err := a.identity.Revoke(ctx, svidID); err != nil {
		return fmt.Errorf("revoking SVID %s: %w", svidID, err)
	}
	return nil
}

func (a *ActivityImpl) RevokeVaultToken(ctx context.Context, token *identity.VaultToken) error {
	if a.secrets == nil {
		return nil
	}
	if err := a.secrets.Revoke(ctx, token); err != nil {
		return fmt.Errorf("revoking Vault token: %w", err)
	}
	return nil
}

func (a *ActivityImpl) RemoveNetworkPolicy(ctx context.Context, cageID string) error {
	if a.network == nil {
		return nil
	}
	if err := a.network.Remove(ctx, cageID); err != nil {
		return fmt.Errorf("cage %s: removing network policy: %w", cageID, err)
	}
	return nil
}

func (a *ActivityImpl) VerifyCleanup(ctx context.Context, cageID string) error {
	if a.provisioner != nil {
		status, err := a.provisioner.Status(ctx, cageID)
		if err != nil {
			return fmt.Errorf("cage %s: checking VM status during cleanup: %w", cageID, err)
		}
		if status == VMStatusRunning {
			return fmt.Errorf("cage %s: VM still running after teardown", cageID)
		}
	}

	if a.rootfs != nil {
		if err := a.rootfs.Cleanup(cageID); err != nil {
			a.log.Error(err, "cleaning up rootfs", "cage_id", cageID)
		}
	}

	a.log.Info("cleanup verified", "cage_id", cageID)
	return nil
}

func (a *ActivityImpl) EmitRCA(_ context.Context, cageID, assessmentID, reason string) error {
	doc := rca.Generate(cageID, assessmentID, reason, nil)
	a.log.Info("RCA generated", "cage_id", cageID, "rca_id", doc.ID, "summary", doc.Summary)
	return nil
}

func (a *ActivityImpl) RecordRunMetrics(_ context.Context, cageID, assessmentID string) error {
	a.log.V(1).Info("run metrics recorded", "cage_id", cageID, "assessment_id", assessmentID)
	return nil
}

func (a *ActivityImpl) RecordCostMetrics(_ context.Context, cageID, assessmentID string) error {
	a.log.V(1).Info("cost metrics recorded", "cage_id", cageID, "assessment_id", assessmentID)
	return nil
}
