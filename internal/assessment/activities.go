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
	CreateValidatorCage(ctx context.Context, assessmentID string, finding findings.Finding, playbook *Playbook) (string, error)
	CreateEscalationCage(ctx context.Context, assessmentID string, finding findings.Finding, config cage.Config) (string, error)
	GetCandidateFindings(ctx context.Context, assessmentID string) ([]findings.Finding, error)
	GetValidatedFindings(ctx context.Context, assessmentID string) ([]findings.Finding, error)
	UpdateFindingStatus(ctx context.Context, findingID string, status findings.Status) error
	UpdateAssessmentStatus(ctx context.Context, assessmentID string, status Status) error
	GenerateReport(ctx context.Context, assessmentID string, validated []findings.Finding) ([]byte, error)
}
