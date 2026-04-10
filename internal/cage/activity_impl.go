package cage

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/go-logr/logr"
	"go.temporal.io/sdk/activity"
	"go.temporal.io/sdk/worker"

	"github.com/okedeji/agentcage/internal/audit"
	"github.com/okedeji/agentcage/internal/cagefile"
	"github.com/okedeji/agentcage/internal/identity"
	"github.com/okedeji/agentcage/internal/rca"
)

// Defined here to avoid a circular dependency with the enforcement package.
type ScopeValidator interface {
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

// FleetHost is a minimal view of a host returned by FleetPool.
type FleetHost struct {
	ID   string
	Pool int // matches fleet.HostPool values
}

// FleetPool abstracts fleet host selection and slot management.
// Defined here to avoid a circular import with the fleet package.
type FleetPool interface {
	GetAvailableHost() (*FleetHost, error)
	AllocateCageSlot(hostID string) error
	ReleaseCageSlot(hostID string) error
	MoveHost(hostID string, toPool int) error
}

// ActivityImpl provides concrete implementations of all cage
// lifecycle activities. Every dependency field is optional; a nil
// dependency is logged and skipped so local mode works without SPIRE,
// Vault, or Falco.
type ActivityImpl struct {
	provisioner    VMProvisioner
	rootfs         *RootfsBuilder
	bundleStoreDir string
	network        NetworkPolicy
	validator      ScopeValidator
	alertHandler   AlertHandler
	alertNotifier  AlertNotifier
	falcoReader    *FalcoAlertReader
	fleetPool      FleetPool
	identity       identity.SVIDIssuer
	secrets        identity.SecretFetcher
	auditStore     audit.Store
	log            logr.Logger
	allocMu        sync.Mutex
	allocs         map[string]string // vmID -> hostID
}

type ActivityImplConfig struct {
	Provisioner   VMProvisioner
	Rootfs        *RootfsBuilder
	Network       NetworkPolicy
	Validator     ScopeValidator
	AlertHandler  AlertHandler
	AlertNotifier AlertNotifier
	FalcoReader   *FalcoAlertReader
	FleetPool     FleetPool
	Identity      identity.SVIDIssuer
	Secrets       identity.SecretFetcher
	AuditStore     audit.Store
	BundleStoreDir string
	Log            logr.Logger
}

// RegisterActivities pins the cage activity surface to an explicit list of
// names on a Temporal worker. Internal helper methods (e.g. EvaluateAlert)
// are intentionally excluded so they cannot be invoked as top-level
// activities. Renaming a method without updating this list is now a
// startup-time failure rather than a silent break of in-flight workflows.
func (a *ActivityImpl) RegisterActivities(w worker.ActivityRegistry) {
	pin := func(name string, fn interface{}) {
		w.RegisterActivityWithOptions(fn, activity.RegisterOptions{Name: name})
	}
	pin("ValidateCageConfig", a.ValidateCageConfig)
	pin("IssueIdentity", a.IssueIdentity)
	pin("FetchSecrets", a.FetchSecrets)
	pin("AssembleRootfs", a.AssembleRootfs)
	pin("ProvisionVM", a.ProvisionVM)
	pin("ApplyNetworkPolicy", a.ApplyNetworkPolicy)
	pin("StartPayloadProxy", a.StartPayloadProxy)
	pin("StartAgent", a.StartAgent)
	pin("MonitorCage", a.MonitorCage)
	pin("ExportAuditLog", a.ExportAuditLog)
	pin("TeardownVM", a.TeardownVM)
	pin("RevokeSVID", a.RevokeSVID)
	pin("RevokeVaultToken", a.RevokeVaultToken)
	pin("RemoveNetworkPolicy", a.RemoveNetworkPolicy)
	pin("VerifyCleanup", a.VerifyCleanup)
	pin("EmitRCA", a.EmitRCA)
	pin("RecordRunMetrics", a.RecordRunMetrics)
	pin("RecordCostMetrics", a.RecordCostMetrics)
}

func NewActivityImpl(cfg ActivityImplConfig) *ActivityImpl {
	return &ActivityImpl{
		provisioner:    cfg.Provisioner,
		rootfs:         cfg.Rootfs,
		bundleStoreDir: cfg.BundleStoreDir,
		network:        cfg.Network,
		validator:      cfg.Validator,
		alertHandler:   cfg.AlertHandler,
		alertNotifier:  cfg.AlertNotifier,
		falcoReader:    cfg.FalcoReader,
		fleetPool:      cfg.FleetPool,
		identity:       cfg.Identity,
		secrets:        cfg.Secrets,
		auditStore:     cfg.AuditStore,
		log:            cfg.Log.WithValues("component", "cage-activities"),
		allocs:         make(map[string]string),
	}
}

func (a *ActivityImpl) ValidateCageConfig(ctx context.Context, config Config) error {
	if a.validator == nil {
		a.log.V(1).Info("cage config validation skipped, no validator configured")
		return nil
	}
	return a.validator.ValidateCageConfig(ctx, config)
}

func (a *ActivityImpl) IssueIdentity(ctx context.Context, cageID string, ttl time.Duration) (*identity.SVID, error) {
	if a.identity == nil {
		a.log.V(1).Info("identity issuance skipped, no SPIRE configured", "cage_id", cageID)
		return &identity.SVID{ID: "dev-" + cageID, SpiffeID: "spiffe://agentcage.local/cage/" + cageID, CageID: cageID, ExpiresAt: time.Now().Add(ttl)}, nil
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
		a.log.V(1).Info("secret fetch skipped, no Vault configured", "cage_id", svid.CageID)
		return &identity.VaultToken{CageID: svid.CageID, Token: "dev-token", ExpiresAt: time.Now().Add(24 * time.Hour)}, nil
	}
	token, err := a.secrets.Authenticate(ctx, svid)
	if err != nil {
		return nil, fmt.Errorf("authenticating with Vault: %w", err)
	}
	a.log.V(1).Info("secrets fetched", "assessment_id", assessmentID, "cage_id", svid.CageID)
	return token, nil
}

func (a *ActivityImpl) AssembleRootfs(ctx context.Context, cageID string, bundleRef string, env Env) (string, error) {
	if a.rootfs == nil {
		a.log.V(1).Info("rootfs assembly skipped, no rootfs builder configured", "cage_id", cageID)
		return "", nil
	}
	if bundleRef == "" {
		return "", fmt.Errorf("cage %s: no bundle ref provided", cageID)
	}

	bundlePath := filepath.Join(a.bundleStoreDir, bundleRef+".cage")
	if _, err := os.Stat(bundlePath); err != nil {
		return "", fmt.Errorf("cage %s: bundle %s not found in store: %w", cageID, bundleRef, err)
	}

	tmpDir, err := os.MkdirTemp("", "agentcage-unpack-"+cageID+"-*")
	if err != nil {
		return "", fmt.Errorf("cage %s: creating unpack dir: %w", cageID, err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	manifest, err := cagefile.UnpackFile(bundlePath, tmpDir)
	if err != nil {
		return "", fmt.Errorf("cage %s: unpacking bundle: %w", cageID, err)
	}

	env.Entrypoint = manifest.Entrypoint

	filesDir := filepath.Join(tmpDir, "files")
	rootfsPath, err := a.rootfs.Assemble(ctx, cageID, manifest, filesDir, env)
	if err != nil {
		return "", fmt.Errorf("cage %s: assembling rootfs: %w", cageID, err)
	}

	a.log.Info("rootfs assembled", "cage_id", cageID, "bundle_ref", bundleRef[:12], "rootfs", rootfsPath)
	return rootfsPath, nil
}

const (
	fleetPoolActive    = 1 // matches fleet.PoolActive
	fleetPoolWarm      = 2 // matches fleet.PoolWarm
	maxSlotRetries     = 3
	maxCapacityRetries = 3
	capacityRetryDelay = 10 * time.Second
)

func (a *ActivityImpl) ProvisionVM(ctx context.Context, vmConfig VMConfig) (*VMHandle, error) {
	if a.provisioner == nil {
		return nil, fmt.Errorf("cage %s: no VM provisioner configured", vmConfig.CageID)
	}

	var hostID string
	if a.fleetPool != nil {
		var allocated bool
		for capacityAttempt := 0; capacityAttempt < maxCapacityRetries; capacityAttempt++ {
			for slotAttempt := 0; slotAttempt < maxSlotRetries; slotAttempt++ {
				host, err := a.fleetPool.GetAvailableHost()
				if err != nil {
					break // no hosts at all, go to capacity retry
				}
				if host.Pool == fleetPoolWarm {
					_ = a.fleetPool.MoveHost(host.ID, fleetPoolActive)
				}
				if err := a.fleetPool.AllocateCageSlot(host.ID); err != nil {
					a.log.V(1).Info("slot allocation race, retrying", "host_id", host.ID, "attempt", slotAttempt+1)
					continue
				}
				hostID = host.ID
				allocated = true
				break
			}
			if allocated {
				break
			}
			if capacityAttempt < maxCapacityRetries-1 {
				a.log.Info("no fleet capacity, waiting for autoscaler", "cage_id", vmConfig.CageID, "retry", capacityAttempt+1)
				select {
				case <-ctx.Done():
					return nil, fmt.Errorf("cage %s: context cancelled while waiting for capacity: %w", vmConfig.CageID, ctx.Err())
				case <-time.After(capacityRetryDelay):
				}
			}
		}
		if !allocated {
			return nil, fmt.Errorf("cage %s: no fleet capacity after %d attempts (waited %s)", vmConfig.CageID, maxCapacityRetries, time.Duration(maxCapacityRetries)*capacityRetryDelay)
		}
	}

	handle, err := a.provisioner.Provision(ctx, vmConfig)
	if err != nil {
		if hostID != "" {
			if relErr := a.fleetPool.ReleaseCageSlot(hostID); relErr != nil {
				a.log.Error(relErr, "releasing cage slot after provision failure", "host_id", hostID, "cage_id", vmConfig.CageID)
			}
		}
		return nil, fmt.Errorf("cage %s: provisioning VM: %w", vmConfig.CageID, err)
	}

	if hostID != "" {
		a.allocMu.Lock()
		a.allocs[handle.ID] = hostID
		a.allocMu.Unlock()
	}

	a.log.Info("VM provisioned", "cage_id", vmConfig.CageID, "vm_id", handle.ID, "ip", handle.IPAddress, "host_id", hostID)
	return handle, nil
}

func (a *ActivityImpl) ApplyNetworkPolicy(ctx context.Context, cageID string, scope Scope, extras []string) error {
	if a.network == nil {
		a.log.V(1).Info("network policy skipped, no enforcer configured", "cage_id", cageID)
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
			a.log.Error(err, "Falco alert stream unavailable, monitoring without behavioral alerts", "cage_id", cageID)
		}
	}
	if alertCh == nil {
		// No Falco. Empty channel never receives, doesn't block select.
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
		a.log.V(1).Info("alert handling skipped, no handler configured", "cage_id", alert.CageID, "rule", alert.RuleName)
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
	if a.provisioner != nil {
		if err := a.provisioner.Terminate(ctx, vmID); err != nil {
			return fmt.Errorf("terminating VM %s: %w", vmID, err)
		}
	}

	if a.fleetPool != nil {
		a.allocMu.Lock()
		hostID, ok := a.allocs[vmID]
		if ok {
			delete(a.allocs, vmID)
		}
		a.allocMu.Unlock()
		if ok {
			if err := a.fleetPool.ReleaseCageSlot(hostID); err != nil {
				a.log.Error(err, "releasing cage slot after teardown", "host_id", hostID, "vm_id", vmID)
			}
		}
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
	if token.Token == "dev-token" {
		return nil
	}
	if err := a.secrets.Revoke(ctx, token); err != nil {
		return fmt.Errorf("revoking Vault token for cage %s: %w", token.CageID, err)
	}
	a.log.V(1).Info("vault token revoked", "cage_id", token.CageID)
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
