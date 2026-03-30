package cage

import (
	"time"

	"github.com/okedeji/agentcage/internal/config"
)

// Timeouts holds activity timeout and heartbeat durations read from config.
type Timeouts struct {
	ValidateScope    time.Duration
	IssueIdentity    time.Duration
	FetchSecrets     time.Duration
	ProvisionVM      time.Duration
	ApplyPolicy      time.Duration
	StartAgent       time.Duration
	ExportAuditLog   time.Duration
	TeardownVM       time.Duration
	RevokeSVID       time.Duration
	RevokeVaultToken time.Duration
	VerifyCleanup    time.Duration

	HeartbeatProvisionVM time.Duration
	HeartbeatMonitorCage time.Duration
}

// TimeoutsFromConfig builds a Timeouts value from the parsed configuration.
func TimeoutsFromConfig(at config.ActivityTimeoutsConfig) Timeouts {
	return Timeouts{
		ValidateScope:        at.ValidateScope,
		IssueIdentity:        at.IssueIdentity,
		FetchSecrets:         at.FetchSecrets,
		ProvisionVM:          at.ProvisionVM,
		ApplyPolicy:          at.ApplyPolicy,
		StartAgent:           at.StartAgent,
		ExportAuditLog:       at.ExportAuditLog,
		TeardownVM:           at.TeardownVM,
		RevokeSVID:           at.RevokeSVID,
		RevokeVaultToken:     at.RevokeVaultToken,
		VerifyCleanup:        at.VerifyCleanup,
		HeartbeatProvisionVM: at.HeartbeatProvisionVM,
		HeartbeatMonitorCage: at.HeartbeatMonitorCage,
	}
}
