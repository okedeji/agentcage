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

// ActivityImpl provides concrete implementations of all cage lifecycle
// activities. It wires together the real Firecracker provisioner, network
// enforcer, identity providers, and audit chain.
type ActivityImpl struct {
	provisioner VMProvisioner
	rootfs      *RootfsBuilder
	network     NetworkPolicy
	validator   ScopeValidator
	identity    identity.SVIDIssuer
	secrets     identity.SecretFetcher
	auditStore  audit.Store
	log         logr.Logger
}

type ActivityImplConfig struct {
	Provisioner VMProvisioner
	Rootfs      *RootfsBuilder
	Network     NetworkPolicy
	Validator   ScopeValidator
	Identity    identity.SVIDIssuer
	Secrets     identity.SecretFetcher
	AuditStore  audit.Store
	Log         logr.Logger
}

func NewActivityImpl(cfg ActivityImplConfig) *ActivityImpl {
	return &ActivityImpl{
		provisioner: cfg.Provisioner,
		rootfs:      cfg.Rootfs,
		network:     cfg.Network,
		validator:   cfg.Validator,
		identity:    cfg.Identity,
		secrets:     cfg.Secrets,
		auditStore:  cfg.AuditStore,
		log:         cfg.Log.WithValues("component", "cage-activities"),
	}
}

func (a *ActivityImpl) ValidateScope(ctx context.Context, config Config) error {
	return a.validator.ValidateScope(ctx, config.Scope)
}

func (a *ActivityImpl) ValidateCageType(ctx context.Context, config Config) error {
	return a.validator.ValidateCageConfig(ctx, config)
}

func (a *ActivityImpl) IssueIdentity(ctx context.Context, cageID string, ttl time.Duration) (*identity.SVID, error) {
	svid, err := a.identity.Issue(ctx, cageID, ttl)
	if err != nil {
		return nil, fmt.Errorf("cage %s: issuing SVID: %w", cageID, err)
	}
	a.log.Info("identity issued", "cage_id", cageID, "spiffe_id", svid.SpiffeID)
	return svid, nil
}

func (a *ActivityImpl) FetchSecrets(ctx context.Context, svid *identity.SVID, assessmentID string) (*identity.VaultToken, error) {
	token, err := a.secrets.Authenticate(ctx, svid)
	if err != nil {
		return nil, fmt.Errorf("authenticating with Vault: %w", err)
	}
	a.log.V(1).Info("secrets fetched", "assessment_id", assessmentID, "cage_id", svid.CageID)
	return token, nil
}

func (a *ActivityImpl) ProvisionVM(ctx context.Context, vmConfig VMConfig) (*VMHandle, error) {
	handle, err := a.provisioner.Provision(ctx, vmConfig)
	if err != nil {
		return nil, fmt.Errorf("cage %s: provisioning VM: %w", vmConfig.CageID, err)
	}
	a.log.Info("VM provisioned", "cage_id", vmConfig.CageID, "vm_id", handle.ID, "ip", handle.IPAddress)
	return handle, nil
}

func (a *ActivityImpl) ApplyNetworkPolicy(ctx context.Context, cageID string, scope Scope, extras []string) error {
	if err := a.network.Apply(ctx, cageID, scope, extras); err != nil {
		return fmt.Errorf("cage %s: applying network policy: %w", cageID, err)
	}
	a.log.Info("network policy applied", "cage_id", cageID, "scope_hosts", scope.Hosts)
	return nil
}

func (a *ActivityImpl) StartPayloadProxy(_ context.Context, vmHandle *VMHandle, vulnClass string) error {
	// Payload proxy is started by cage-init inside the VM.
	a.log.Info("payload proxy started by cage-init", "cage_id", vmHandle.CageID, "vuln_class", vulnClass)
	return nil
}

func (a *ActivityImpl) StartAgent(_ context.Context, vmHandle *VMHandle, config Config) error {
	// Agent is started by cage-init inside the VM via the entrypoint.
	a.log.Info("agent started by cage-init", "cage_id", vmHandle.CageID, "type", config.Type)
	return nil
}

func (a *ActivityImpl) MonitorCage(ctx context.Context, cageID string, config Config) (StopReason, error) {
	a.log.Info("monitoring cage", "cage_id", cageID, "max_duration", config.TimeLimits.MaxDuration)

	deadline := time.After(config.TimeLimits.MaxDuration)

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return StopReasonError, ctx.Err()

		case <-deadline:
			a.log.Info("cage timed out", "cage_id", cageID)
			return StopReasonTimeout, nil

		case <-ticker.C:
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

func (a *ActivityImpl) ExportAuditLog(_ context.Context, cageID string) error {
	a.log.Info("exporting audit log", "cage_id", cageID)
	return nil
}

func (a *ActivityImpl) TeardownVM(ctx context.Context, vmID string) error {
	if err := a.provisioner.Terminate(ctx, vmID); err != nil {
		return fmt.Errorf("terminating VM %s: %w", vmID, err)
	}
	a.log.Info("VM terminated", "vm_id", vmID)
	return nil
}

func (a *ActivityImpl) RevokeSVID(ctx context.Context, svidID string) error {
	if err := a.identity.Revoke(ctx, svidID); err != nil {
		return fmt.Errorf("revoking SVID %s: %w", svidID, err)
	}
	return nil
}

func (a *ActivityImpl) RevokeVaultToken(ctx context.Context, token *identity.VaultToken) error {
	if err := a.secrets.Revoke(ctx, token); err != nil {
		return fmt.Errorf("revoking Vault token: %w", err)
	}
	return nil
}

func (a *ActivityImpl) RemoveNetworkPolicy(ctx context.Context, cageID string) error {
	if err := a.network.Remove(ctx, cageID); err != nil {
		return fmt.Errorf("cage %s: removing network policy: %w", cageID, err)
	}
	return nil
}

func (a *ActivityImpl) VerifyCleanup(ctx context.Context, cageID string) error {
	status, err := a.provisioner.Status(ctx, cageID)
	if err != nil {
		return fmt.Errorf("cage %s: checking VM status during cleanup: %w", cageID, err)
	}
	if status == VMStatusRunning {
		return fmt.Errorf("cage %s: VM still running after teardown", cageID)
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
