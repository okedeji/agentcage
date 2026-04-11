package cage

import (
	"context"
	"time"

	"github.com/okedeji/agentcage/internal/identity"
)

// StopReason indicates why the MonitorCage activity ended.
type StopReason int

const (
	StopReasonCompleted StopReason = iota + 1
	StopReasonTimeout
	StopReasonTripwire
	StopReasonBudgetExhausted
	StopReasonError
)

func (r StopReason) String() string {
	switch r {
	case StopReasonCompleted:
		return "completed"
	case StopReasonTimeout:
		return "timeout"
	case StopReasonTripwire:
		return "tripwire"
	case StopReasonBudgetExhausted:
		return "budget_exhausted"
	case StopReasonError:
		return "error"
	default:
		return "unknown"
	}
}

func (r StopReason) RequiresRCA() bool {
	return r == StopReasonTripwire || r == StopReasonError
}

// Activities defines the operations the cage workflow can invoke.
// Each method maps to a Temporal activity. Implementations are
// provided by the orchestrator binary, which wires the real
// dependencies (SPIRE, Vault, Cilium, Firecracker, etc.).
type Activities interface {
	ValidateCageConfig(ctx context.Context, config Config) error
	IssueIdentity(ctx context.Context, cageID string, ttl time.Duration) (*identity.SVID, error)
	FetchSecrets(ctx context.Context, svid *identity.SVID, assessmentID string) (*identity.VaultToken, error)
	AssembleRootfs(ctx context.Context, cageID string, bundleRef string, env Env) (string, error)
	ProvisionVM(ctx context.Context, vmConfig VMConfig) (*VMHandle, error)
	ApplyNetworkPolicy(ctx context.Context, cageID string, scope Scope, extras []string) error
	MonitorCage(ctx context.Context, cageID, vmID string, config Config) (StopReason, error)
	ExportAuditLog(ctx context.Context, cageID string) error
	TeardownVM(ctx context.Context, vmID string) error
	RevokeSVID(ctx context.Context, svidID string) error
	RevokeVaultToken(ctx context.Context, token *identity.VaultToken) error
	RemoveNetworkPolicy(ctx context.Context, cageID string) error
	VerifyCleanup(ctx context.Context, cageID, vmID string) error
	EmitRCA(ctx context.Context, cageID string, assessmentID string, reason string) error
	RecordRunMetrics(ctx context.Context, cageID string, assessmentID string) error
	RecordCostMetrics(ctx context.Context, cageID string, assessmentID string) error
}
