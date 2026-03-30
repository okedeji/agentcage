package cage

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.temporal.io/sdk/testsuite"

	"github.com/okedeji/agentcage/internal/identity"
	"github.com/okedeji/agentcage/internal/intervention"
)

// activityStub is a zero-value implementation of Activities registered with
// the Temporal test environment so that string-based activity names resolve.
// All methods are overridden via env.OnActivity in each test.
type activityStub struct{}

func (activityStub) ValidateScope(context.Context, Config) error { return nil }
func (activityStub) ValidateCageType(context.Context, Config) error { return nil }
func (activityStub) IssueIdentity(context.Context, string, time.Duration) (*identity.SVID, error) {
	return nil, nil
}
func (activityStub) FetchSecrets(context.Context, *identity.SVID, string) (*identity.VaultToken, error) {
	return nil, nil
}
func (activityStub) ProvisionVM(context.Context, VMConfig) (*VMHandle, error) { return nil, nil }
func (activityStub) ApplyNetworkPolicy(context.Context, string, Scope, []string) error {
	return nil
}
func (activityStub) StartPayloadProxy(context.Context, *VMHandle, string) error { return nil }
func (activityStub) StartAgent(context.Context, *VMHandle, Config) error       { return nil }
func (activityStub) MonitorCage(context.Context, string, Config) (StopReason, error) {
	return StopReasonCompleted, nil
}
func (activityStub) ExportAuditLog(context.Context, string) error               { return nil }
func (activityStub) TeardownVM(context.Context, string) error                   { return nil }
func (activityStub) RevokeSVID(context.Context, string) error                   { return nil }
func (activityStub) RevokeVaultToken(context.Context, *identity.VaultToken) error { return nil }
func (activityStub) RemoveNetworkPolicy(context.Context, string) error          { return nil }
func (activityStub) VerifyCleanup(context.Context, string) error                { return nil }
func (activityStub) EmitRCA(context.Context, string, string, string) error      { return nil }
func (activityStub) RecordRunMetrics(context.Context, string, string) error     { return nil }
func (activityStub) RecordCostMetrics(context.Context, string, string) error    { return nil }

func testWorkflowInput() CageWorkflowInput {
	return CageWorkflowInput{
		CageID:      "test-cage-1",
		GatewayAddr: "gateway.internal",
		NATSAddr:    "nats.internal",
		Config: Config{
			AssessmentID: "test-assessment-1",
			Type:         TypeDiscovery,
			Scope:        Scope{Hosts: []string{"target.example.com"}},
			Resources:    ResourceLimits{VCPUs: 2, MemoryMB: 4096},
			TimeLimits:   TimeLimits{MaxDuration: 5 * time.Minute},
			RateLimits:   RateLimits{RequestsPerSecond: 100},
			LLM:          &LLMGatewayConfig{TokenBudget: 100000, RoutingStrategy: "cost_optimized"},
			ProxyConfig:  ProxyConfig{Mode: ProxyModeBlocklist},
		},
		Timeouts: Timeouts{
			ValidateScope:        5 * time.Second,
			IssueIdentity:        10 * time.Second,
			FetchSecrets:         5 * time.Second,
			ProvisionVM:          30 * time.Second,
			ApplyPolicy:          10 * time.Second,
			StartAgent:           5 * time.Second,
			ExportAuditLog:       15 * time.Second,
			TeardownVM:           15 * time.Second,
			RevokeSVID:           5 * time.Second,
			RevokeVaultToken:     5 * time.Second,
			VerifyCleanup:        10 * time.Second,
			HeartbeatProvisionVM: 10 * time.Second,
			HeartbeatMonitorCage: 30 * time.Second,
		},
	}
}

func testSVID() *identity.SVID {
	return &identity.SVID{
		ID:        "svid-1",
		SpiffeID:  "spiffe://agentcage/cage/test-cage-1",
		ExpiresAt: time.Now().Add(time.Hour),
		CageID:    "test-cage-1",
	}
}

func testVaultToken() *identity.VaultToken {
	return &identity.VaultToken{
		Token:     "vault-token-1",
		ExpiresAt: time.Now().Add(time.Hour),
		CageID:    "test-cage-1",
		Policies:  []string{"cage-policy"},
	}
}

func testVMHandle() *VMHandle {
	return &VMHandle{
		ID:         "vm-1",
		CageID:     "test-cage-1",
		IPAddress:  "10.0.0.2",
		SocketPath: "/tmp/firecracker/vm-1.sock",
		StartedAt:  time.Now(),
	}
}

func newTestEnv(t *testing.T) *testsuite.TestWorkflowEnvironment {
	t.Helper()
	s := testsuite.WorkflowTestSuite{}
	env := s.NewTestWorkflowEnvironment()
	env.RegisterActivity(&activityStub{})
	return env
}

func registerHappyPathMocks(env *testsuite.TestWorkflowEnvironment) {
	env.OnActivity("ValidateScope", mock.Anything, mock.Anything).Return(nil)
	env.OnActivity("ValidateCageType", mock.Anything, mock.Anything).Return(nil)
	env.OnActivity("IssueIdentity", mock.Anything, mock.Anything, mock.Anything).Return(testSVID(), nil)
	env.OnActivity("FetchSecrets", mock.Anything, mock.Anything, mock.Anything).Return(testVaultToken(), nil)
	env.OnActivity("ProvisionVM", mock.Anything, mock.Anything).Return(testVMHandle(), nil)
	env.OnActivity("ApplyNetworkPolicy", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil)
	env.OnActivity("StartPayloadProxy", mock.Anything, mock.Anything, mock.Anything).Return(nil)
	env.OnActivity("StartAgent", mock.Anything, mock.Anything, mock.Anything).Return(nil)
	env.OnActivity("MonitorCage", mock.Anything, mock.Anything, mock.Anything).Return(StopReasonCompleted, nil)
	env.OnActivity("ExportAuditLog", mock.Anything, mock.Anything).Return(nil)
	env.OnActivity("TeardownVM", mock.Anything, mock.Anything).Return(nil)
	env.OnActivity("RevokeSVID", mock.Anything, mock.Anything).Return(nil)
	env.OnActivity("RevokeVaultToken", mock.Anything, mock.Anything).Return(nil)
	env.OnActivity("RemoveNetworkPolicy", mock.Anything, mock.Anything).Return(nil)
	env.OnActivity("VerifyCleanup", mock.Anything, mock.Anything).Return(nil)
	env.OnActivity("RecordRunMetrics", mock.Anything, mock.Anything, mock.Anything).Return(nil)
	env.OnActivity("RecordCostMetrics", mock.Anything, mock.Anything, mock.Anything).Return(nil)
}

func TestCageWorkflow_HappyPath(t *testing.T) {
	env := newTestEnv(t)
	registerHappyPathMocks(env)

	env.ExecuteWorkflow(CageWorkflow, testWorkflowInput())
	require.True(t, env.IsWorkflowCompleted())
	require.NoError(t, env.GetWorkflowError())

	var result CageWorkflowResult
	require.NoError(t, env.GetWorkflowResult(&result))
	assert.Equal(t, StateCompleted, result.FinalState)
	assert.Equal(t, StopReasonCompleted, result.StopReason)
	assert.Empty(t, result.Error)
	assert.Equal(t, "test-cage-1", result.CageID)

	env.AssertCalled(t, "TeardownVM", mock.Anything, mock.Anything)
	env.AssertCalled(t, "RevokeSVID", mock.Anything, mock.Anything)
	env.AssertCalled(t, "RevokeVaultToken", mock.Anything, mock.Anything)
	env.AssertCalled(t, "RemoveNetworkPolicy", mock.Anything, mock.Anything)
	env.AssertCalled(t, "VerifyCleanup", mock.Anything, mock.Anything)
}

func TestCageWorkflow_ValidationFailure(t *testing.T) {
	env := newTestEnv(t)
	env.OnActivity("ValidateScope", mock.Anything, mock.Anything).
		Return(errors.New("scope contains internal IP range"))

	env.ExecuteWorkflow(CageWorkflow, testWorkflowInput())
	require.True(t, env.IsWorkflowCompleted())
	require.NoError(t, env.GetWorkflowError())

	var result CageWorkflowResult
	require.NoError(t, env.GetWorkflowResult(&result))
	assert.Equal(t, StateFailed, result.FinalState)
	assert.Contains(t, result.Error, "validating scope")

	env.AssertNotCalled(t, "ProvisionVM", mock.Anything, mock.Anything)
	env.AssertNotCalled(t, "TeardownVM", mock.Anything, mock.Anything)
}

func TestCageWorkflow_ProvisionFailure(t *testing.T) {
	env := newTestEnv(t)
	env.OnActivity("ValidateScope", mock.Anything, mock.Anything).Return(nil)
	env.OnActivity("ValidateCageType", mock.Anything, mock.Anything).Return(nil)
	env.OnActivity("IssueIdentity", mock.Anything, mock.Anything, mock.Anything).Return(testSVID(), nil)
	env.OnActivity("FetchSecrets", mock.Anything, mock.Anything, mock.Anything).Return(testVaultToken(), nil)
	env.OnActivity("ProvisionVM", mock.Anything, mock.Anything).
		Return(nil, errors.New("no hosts available"))
	env.OnActivity("RevokeSVID", mock.Anything, mock.Anything).Return(nil)
	env.OnActivity("RevokeVaultToken", mock.Anything, mock.Anything).Return(nil)

	env.ExecuteWorkflow(CageWorkflow, testWorkflowInput())
	require.True(t, env.IsWorkflowCompleted())
	require.NoError(t, env.GetWorkflowError())

	var result CageWorkflowResult
	require.NoError(t, env.GetWorkflowResult(&result))
	assert.Equal(t, StateFailed, result.FinalState)
	assert.Contains(t, result.Error, "provisioning VM")

	env.AssertCalled(t, "RevokeSVID", mock.Anything, mock.Anything)
	env.AssertCalled(t, "RevokeVaultToken", mock.Anything, mock.Anything)
	env.AssertNotCalled(t, "TeardownVM", mock.Anything, mock.Anything)
}

func TestCageWorkflow_TeardownMultiError(t *testing.T) {
	env := newTestEnv(t)
	env.OnActivity("ValidateScope", mock.Anything, mock.Anything).Return(nil)
	env.OnActivity("ValidateCageType", mock.Anything, mock.Anything).Return(nil)
	env.OnActivity("IssueIdentity", mock.Anything, mock.Anything, mock.Anything).Return(testSVID(), nil)
	env.OnActivity("FetchSecrets", mock.Anything, mock.Anything, mock.Anything).Return(testVaultToken(), nil)
	env.OnActivity("ProvisionVM", mock.Anything, mock.Anything).Return(testVMHandle(), nil)
	env.OnActivity("ApplyNetworkPolicy", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil)
	env.OnActivity("StartPayloadProxy", mock.Anything, mock.Anything, mock.Anything).Return(nil)
	env.OnActivity("StartAgent", mock.Anything, mock.Anything, mock.Anything).Return(nil)
	env.OnActivity("MonitorCage", mock.Anything, mock.Anything, mock.Anything).Return(StopReasonCompleted, nil)
	env.OnActivity("ExportAuditLog", mock.Anything, mock.Anything).Return(nil)
	env.OnActivity("TeardownVM", mock.Anything, mock.Anything).Return(errors.New("VM stuck"))
	env.OnActivity("RevokeSVID", mock.Anything, mock.Anything).Return(errors.New("SPIRE unavailable"))
	env.OnActivity("RevokeVaultToken", mock.Anything, mock.Anything).Return(nil)
	env.OnActivity("RemoveNetworkPolicy", mock.Anything, mock.Anything).Return(nil)
	env.OnActivity("VerifyCleanup", mock.Anything, mock.Anything).Return(nil)
	env.OnActivity("RecordRunMetrics", mock.Anything, mock.Anything, mock.Anything).Return(nil)
	env.OnActivity("RecordCostMetrics", mock.Anything, mock.Anything, mock.Anything).Return(nil)

	env.ExecuteWorkflow(CageWorkflow, testWorkflowInput())
	require.True(t, env.IsWorkflowCompleted())
	require.NoError(t, env.GetWorkflowError())

	var result CageWorkflowResult
	require.NoError(t, env.GetWorkflowResult(&result))
	assert.Equal(t, StateFailed, result.FinalState)
	assert.Contains(t, result.Error, "tearing down VM")
	assert.Contains(t, result.Error, "revoking SVID")

	env.AssertCalled(t, "RevokeVaultToken", mock.Anything, mock.Anything)
	env.AssertCalled(t, "RemoveNetworkPolicy", mock.Anything, mock.Anything)
	env.AssertCalled(t, "VerifyCleanup", mock.Anything, mock.Anything)
}

func TestCageWorkflow_SignalKill(t *testing.T) {
	env := newTestEnv(t)
	env.OnActivity("ValidateScope", mock.Anything, mock.Anything).Return(nil)
	env.OnActivity("ValidateCageType", mock.Anything, mock.Anything).Return(nil)
	env.OnActivity("IssueIdentity", mock.Anything, mock.Anything, mock.Anything).Return(testSVID(), nil)
	env.OnActivity("FetchSecrets", mock.Anything, mock.Anything, mock.Anything).Return(testVaultToken(), nil)
	env.OnActivity("ProvisionVM", mock.Anything, mock.Anything).Return(testVMHandle(), nil)
	env.OnActivity("ApplyNetworkPolicy", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil)
	env.OnActivity("StartPayloadProxy", mock.Anything, mock.Anything, mock.Anything).Return(nil)
	env.OnActivity("StartAgent", mock.Anything, mock.Anything, mock.Anything).Return(nil)
	env.OnActivity("MonitorCage", mock.Anything, mock.Anything, mock.Anything).
		Return(StopReasonCompleted, nil).
		After(10 * time.Minute)
	env.OnActivity("ExportAuditLog", mock.Anything, mock.Anything).Return(nil)
	env.OnActivity("TeardownVM", mock.Anything, mock.Anything).Return(nil)
	env.OnActivity("RevokeSVID", mock.Anything, mock.Anything).Return(nil)
	env.OnActivity("RevokeVaultToken", mock.Anything, mock.Anything).Return(nil)
	env.OnActivity("RemoveNetworkPolicy", mock.Anything, mock.Anything).Return(nil)
	env.OnActivity("VerifyCleanup", mock.Anything, mock.Anything).Return(nil)
	env.OnActivity("EmitRCA", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil)
	env.OnActivity("RecordRunMetrics", mock.Anything, mock.Anything, mock.Anything).Return(nil)
	env.OnActivity("RecordCostMetrics", mock.Anything, mock.Anything, mock.Anything).Return(nil)

	env.RegisterDelayedCallback(func() {
		env.SignalWorkflow(intervention.SignalIntervention, intervention.InterventionSignal{
			Action:    intervention.ActionKill,
			Rationale: "operator kill",
		})
	}, 2*time.Second)

	env.ExecuteWorkflow(CageWorkflow, testWorkflowInput())
	require.True(t, env.IsWorkflowCompleted())
	require.NoError(t, env.GetWorkflowError())

	var result CageWorkflowResult
	require.NoError(t, env.GetWorkflowResult(&result))
	assert.Equal(t, StopReasonTripwire, result.StopReason)
	assert.Equal(t, StateFailed, result.FinalState)

	env.AssertCalled(t, "TeardownVM", mock.Anything, mock.Anything)
	env.AssertCalled(t, "EmitRCA", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

func TestCageWorkflow_MonitorTimeout(t *testing.T) {
	env := newTestEnv(t)
	env.OnActivity("ValidateScope", mock.Anything, mock.Anything).Return(nil)
	env.OnActivity("ValidateCageType", mock.Anything, mock.Anything).Return(nil)
	env.OnActivity("IssueIdentity", mock.Anything, mock.Anything, mock.Anything).Return(testSVID(), nil)
	env.OnActivity("FetchSecrets", mock.Anything, mock.Anything, mock.Anything).Return(testVaultToken(), nil)
	env.OnActivity("ProvisionVM", mock.Anything, mock.Anything).Return(testVMHandle(), nil)
	env.OnActivity("ApplyNetworkPolicy", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil)
	env.OnActivity("StartPayloadProxy", mock.Anything, mock.Anything, mock.Anything).Return(nil)
	env.OnActivity("StartAgent", mock.Anything, mock.Anything, mock.Anything).Return(nil)
	env.OnActivity("MonitorCage", mock.Anything, mock.Anything, mock.Anything).Return(StopReasonTimeout, nil)
	env.OnActivity("ExportAuditLog", mock.Anything, mock.Anything).Return(nil)
	env.OnActivity("TeardownVM", mock.Anything, mock.Anything).Return(nil)
	env.OnActivity("RevokeSVID", mock.Anything, mock.Anything).Return(nil)
	env.OnActivity("RevokeVaultToken", mock.Anything, mock.Anything).Return(nil)
	env.OnActivity("RemoveNetworkPolicy", mock.Anything, mock.Anything).Return(nil)
	env.OnActivity("VerifyCleanup", mock.Anything, mock.Anything).Return(nil)
	env.OnActivity("RecordRunMetrics", mock.Anything, mock.Anything, mock.Anything).Return(nil)
	env.OnActivity("RecordCostMetrics", mock.Anything, mock.Anything, mock.Anything).Return(nil)

	env.ExecuteWorkflow(CageWorkflow, testWorkflowInput())
	require.True(t, env.IsWorkflowCompleted())
	require.NoError(t, env.GetWorkflowError())

	var result CageWorkflowResult
	require.NoError(t, env.GetWorkflowResult(&result))
	assert.Equal(t, StopReasonTimeout, result.StopReason)
	assert.Equal(t, StateCompleted, result.FinalState)
	assert.Empty(t, result.Error)
}

func TestCageWorkflow_FetchSecretsFailure_CleansUpSVID(t *testing.T) {
	env := newTestEnv(t)
	env.OnActivity("ValidateScope", mock.Anything, mock.Anything).Return(nil)
	env.OnActivity("ValidateCageType", mock.Anything, mock.Anything).Return(nil)
	env.OnActivity("IssueIdentity", mock.Anything, mock.Anything, mock.Anything).Return(testSVID(), nil)
	env.OnActivity("FetchSecrets", mock.Anything, mock.Anything, mock.Anything).
		Return(nil, errors.New("Vault sealed"))
	env.OnActivity("RevokeSVID", mock.Anything, mock.Anything).Return(nil)

	env.ExecuteWorkflow(CageWorkflow, testWorkflowInput())
	require.True(t, env.IsWorkflowCompleted())
	require.NoError(t, env.GetWorkflowError())

	var result CageWorkflowResult
	require.NoError(t, env.GetWorkflowResult(&result))
	assert.Equal(t, StateFailed, result.FinalState)
	assert.Contains(t, result.Error, "fetching secrets")

	env.AssertCalled(t, "RevokeSVID", mock.Anything, mock.Anything)
	env.AssertNotCalled(t, "RevokeVaultToken", mock.Anything, mock.Anything)
	env.AssertNotCalled(t, "ProvisionVM", mock.Anything, mock.Anything)
}

func TestCageWorkflow_ProxyDisabled(t *testing.T) {
	env := newTestEnv(t)
	registerHappyPathMocks(env)

	input := testWorkflowInput()
	input.Config.ProxyConfig.Mode = ProxyModeDisabled

	env.ExecuteWorkflow(CageWorkflow, input)
	require.True(t, env.IsWorkflowCompleted())
	require.NoError(t, env.GetWorkflowError())

	var result CageWorkflowResult
	require.NoError(t, env.GetWorkflowResult(&result))
	assert.Equal(t, StateCompleted, result.FinalState)

	env.AssertNotCalled(t, "StartPayloadProxy", mock.Anything, mock.Anything, mock.Anything)
}
