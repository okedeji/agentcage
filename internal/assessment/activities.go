package assessment

import (
	"context"

	"github.com/okedeji/agentcage/internal/cage"
	"github.com/okedeji/agentcage/internal/findings"
)

type TaskMatrixEntry struct {
	Endpoint  string
	Parameter string
	Method    string
	VulnClass string
}

type Activities interface {
	CreateDiscoveryCage(ctx context.Context, assessmentID string, config cage.Config) (string, error)
	CreateValidatorCage(ctx context.Context, assessmentID string, finding findings.Finding, proof *Proof, bundleRef string) (string, error)
	CreateEscalationCage(ctx context.Context, assessmentID string, finding findings.Finding, config cage.Config) (string, error)
	GetCandidateFindings(ctx context.Context, assessmentID string) ([]findings.Finding, error)
	GetValidatedFindings(ctx context.Context, assessmentID string) ([]findings.Finding, error)
	UpdateFindingStatus(ctx context.Context, findingID string, status findings.Status) error
	UpdateAssessmentStatus(ctx context.Context, assessmentID string, status Status) error
	GenerateReport(ctx context.Context, assessmentID string, validated []findings.Finding) ([]byte, error)
	PlanNextActions(ctx context.Context, state CoordinatorState) (CoordinatorDecision, error)
	LookupProof(ctx context.Context, vulnClass string) (*Proof, error)
	GetFinding(ctx context.Context, findingID string) (findings.Finding, error)
	EmitProofGapIntervention(ctx context.Context, assessmentID, vulnClass string, findingIDs []string) (string, error)
	NotifyAssessmentComplete(ctx context.Context, assessmentID string, config NotificationConfig, status Status, findingsValidated int32, name string, tags map[string]string) error
}
