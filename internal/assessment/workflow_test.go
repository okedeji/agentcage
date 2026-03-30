package assessment

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.temporal.io/sdk/testsuite"

	"github.com/okedeji/agentcage/internal/cage"
	"github.com/okedeji/agentcage/internal/findings"
	"github.com/okedeji/agentcage/internal/intervention"
)

type assessmentActivityStub struct{}

func (assessmentActivityStub) CreateDiscoveryCage(_ context.Context, _ string, _ cage.Config) (string, error) {
	return "", nil
}
func (assessmentActivityStub) CreateValidatorCage(_ context.Context, _ string, _ findings.Finding, _ *Playbook) (string, error) {
	return "", nil
}
func (assessmentActivityStub) CreateEscalationCage(_ context.Context, _ string, _ findings.Finding, _ cage.Config) (string, error) {
	return "", nil
}
func (assessmentActivityStub) GetCandidateFindings(_ context.Context, _ string) ([]findings.Finding, error) {
	return nil, nil
}
func (assessmentActivityStub) GetValidatedFindings(_ context.Context, _ string) ([]findings.Finding, error) {
	return nil, nil
}
func (assessmentActivityStub) UpdateFindingStatus(_ context.Context, _ string, _ findings.Status) error {
	return nil
}
func (assessmentActivityStub) UpdateAssessmentStatus(_ context.Context, _ string, _ Status) error {
	return nil
}
func (assessmentActivityStub) GenerateReport(_ context.Context, _ string, _ []findings.Finding) ([]byte, error) {
	return nil, nil
}

func testInput() AssessmentWorkflowInput {
	return AssessmentWorkflowInput{
		AssessmentID: "test-assessment-1",
		Config: Config{
			CustomerID:    "customer-1",
			Scope:         cage.Scope{Hosts: []string{"target.example.com"}},
			TokenBudget:   1000000,
			MaxDuration:   2 * time.Hour,
			MaxChainDepth: 3,
		},
	}
}

func newAssessmentTestEnv(t *testing.T) *testsuite.TestWorkflowEnvironment {
	t.Helper()
	s := testsuite.WorkflowTestSuite{}
	env := s.NewTestWorkflowEnvironment()
	env.RegisterActivity(&assessmentActivityStub{})
	return env
}

func candidateFinding(id, endpoint, vulnClass string, severity findings.Severity) findings.Finding {
	return findings.Finding{
		ID:        id,
		Endpoint:  endpoint,
		VulnClass: vulnClass,
		Status:    findings.StatusCandidate,
		Severity:  severity,
	}
}

func validatedFinding(id string, severity findings.Severity) findings.Finding {
	return findings.Finding{
		ID:       id,
		Status:   findings.StatusValidated,
		Severity: severity,
	}
}

func registerAssessmentHappyPathMocks(env *testsuite.TestWorkflowEnvironment) {
	env.OnActivity("UpdateAssessmentStatus", mock.Anything, mock.Anything, mock.Anything).Return(nil)
	env.OnActivity("CreateDiscoveryCage", mock.Anything, mock.Anything, mock.Anything).Return("cage-1", nil)

	surfaceFindings := []findings.Finding{
		candidateFinding("f-1", "https://target.example.com/api", "sqli", findings.SeverityHigh),
		candidateFinding("f-2", "https://target.example.com/login", "xss", findings.SeverityMedium),
	}

	// First call returns surface mapping results; subsequent calls return the same.
	env.OnActivity("GetCandidateFindings", mock.Anything, mock.Anything).Return(surfaceFindings, nil)

	env.OnActivity("CreateValidatorCage", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return("cage-v-1", nil)

	validatedFindings := []findings.Finding{
		validatedFinding("f-1", findings.SeverityHigh),
	}
	env.OnActivity("GetValidatedFindings", mock.Anything, mock.Anything).Return(validatedFindings, nil)

	env.OnActivity("CreateEscalationCage", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return("cage-e-1", nil)

	env.OnActivity("GenerateReport", mock.Anything, mock.Anything, mock.Anything).Return([]byte("report"), nil)
}

func TestAssessmentWorkflow_HappyPath(t *testing.T) {
	env := newAssessmentTestEnv(t)
	registerAssessmentHappyPathMocks(env)

	env.RegisterDelayedCallback(func() {
		env.SignalWorkflow(intervention.SignalReportReview, intervention.ReportReviewSignal{
			Decision:  intervention.ReviewApprove,
			Rationale: "looks good",
		})
	}, TimeoutWaitForCage*4+1*time.Second)

	env.ExecuteWorkflow(AssessmentWorkflow, testInput())
	require.True(t, env.IsWorkflowCompleted())
	require.NoError(t, env.GetWorkflowError())

	var result AssessmentWorkflowResult
	require.NoError(t, env.GetWorkflowResult(&result))
	assert.Equal(t, StatusApproved, result.FinalStatus)
	assert.Equal(t, "test-assessment-1", result.AssessmentID)
	assert.Greater(t, result.TotalCages, int32(0))
	assert.Empty(t, result.Error)

	env.AssertCalled(t, "GenerateReport", mock.Anything, mock.Anything, mock.Anything)
}

func TestAssessmentWorkflow_NoFindings(t *testing.T) {
	env := newAssessmentTestEnv(t)

	env.OnActivity("UpdateAssessmentStatus", mock.Anything, mock.Anything, mock.Anything).Return(nil)
	env.OnActivity("CreateDiscoveryCage", mock.Anything, mock.Anything, mock.Anything).Return("cage-1", nil)
	env.OnActivity("GetCandidateFindings", mock.Anything, mock.Anything).Return([]findings.Finding{}, nil)
	env.OnActivity("GetValidatedFindings", mock.Anything, mock.Anything).Return([]findings.Finding{}, nil)
	env.OnActivity("GenerateReport", mock.Anything, mock.Anything, mock.Anything).Return([]byte("empty report"), nil)

	env.RegisterDelayedCallback(func() {
		env.SignalWorkflow(intervention.SignalReportReview, intervention.ReportReviewSignal{
			Decision:  intervention.ReviewApprove,
			Rationale: "no findings, approved",
		})
	}, TimeoutWaitForCage+1*time.Second)

	env.ExecuteWorkflow(AssessmentWorkflow, testInput())
	require.True(t, env.IsWorkflowCompleted())
	require.NoError(t, env.GetWorkflowError())

	var result AssessmentWorkflowResult
	require.NoError(t, env.GetWorkflowResult(&result))
	assert.Equal(t, StatusApproved, result.FinalStatus)
	assert.Equal(t, int32(0), result.Findings)
	assert.Empty(t, result.Error)
}

func TestAssessmentWorkflow_ReportRejected(t *testing.T) {
	env := newAssessmentTestEnv(t)
	registerAssessmentHappyPathMocks(env)

	env.RegisterDelayedCallback(func() {
		env.SignalWorkflow(intervention.SignalReportReview, intervention.ReportReviewSignal{
			Decision:  intervention.ReviewReject,
			Rationale: "insufficient evidence",
		})
	}, TimeoutWaitForCage*4+1*time.Second)

	env.ExecuteWorkflow(AssessmentWorkflow, testInput())
	require.True(t, env.IsWorkflowCompleted())
	require.NoError(t, env.GetWorkflowError())

	var result AssessmentWorkflowResult
	require.NoError(t, env.GetWorkflowResult(&result))
	assert.Equal(t, StatusRejected, result.FinalStatus)
	assert.Empty(t, result.Error)
}

func TestAssessmentWorkflow_ReviewTimeout(t *testing.T) {
	env := newAssessmentTestEnv(t)
	registerAssessmentHappyPathMocks(env)

	// No signal sent — let the 24h timer fire.

	env.ExecuteWorkflow(AssessmentWorkflow, testInput())
	require.True(t, env.IsWorkflowCompleted())
	require.NoError(t, env.GetWorkflowError())

	var result AssessmentWorkflowResult
	require.NoError(t, env.GetWorkflowResult(&result))
	assert.Equal(t, StatusRejected, result.FinalStatus)
	assert.Empty(t, result.Error)
}

func TestAssessmentWorkflow_ChainDepthEnforced(t *testing.T) {
	env := newAssessmentTestEnv(t)

	env.OnActivity("UpdateAssessmentStatus", mock.Anything, mock.Anything, mock.Anything).Return(nil)
	env.OnActivity("CreateDiscoveryCage", mock.Anything, mock.Anything, mock.Anything).Return("cage-1", nil)

	surfaceFindings := []findings.Finding{
		candidateFinding("f-1", "https://target.example.com/api", "sqli", findings.SeverityCritical),
	}
	env.OnActivity("GetCandidateFindings", mock.Anything, mock.Anything).Return(surfaceFindings, nil)
	env.OnActivity("CreateValidatorCage", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return("cage-v-1", nil)

	atMaxDepth := findings.Finding{
		ID:         "f-1",
		Status:     findings.StatusValidated,
		Severity:   findings.SeverityCritical,
		ChainDepth: 3,
	}
	env.OnActivity("GetValidatedFindings", mock.Anything, mock.Anything).Return([]findings.Finding{atMaxDepth}, nil)
	env.OnActivity("GenerateReport", mock.Anything, mock.Anything, mock.Anything).Return([]byte("report"), nil)

	env.RegisterDelayedCallback(func() {
		env.SignalWorkflow(intervention.SignalReportReview, intervention.ReportReviewSignal{
			Decision:  intervention.ReviewApprove,
			Rationale: "approved",
		})
	}, TimeoutWaitForCage*4+1*time.Second)

	env.ExecuteWorkflow(AssessmentWorkflow, testInput())
	require.True(t, env.IsWorkflowCompleted())
	require.NoError(t, env.GetWorkflowError())

	var result AssessmentWorkflowResult
	require.NoError(t, env.GetWorkflowResult(&result))
	assert.Equal(t, StatusApproved, result.FinalStatus)

	env.AssertNotCalled(t, "CreateEscalationCage", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}
