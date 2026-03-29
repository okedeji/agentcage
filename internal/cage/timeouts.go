package cage

import "time"

const (
	TimeoutValidateScope    = 5 * time.Second
	TimeoutIssueIdentity    = 10 * time.Second
	TimeoutFetchSecrets     = 5 * time.Second
	TimeoutProvisionVM      = 30 * time.Second
	TimeoutApplyPolicy      = 10 * time.Second
	TimeoutStartAgent       = 5 * time.Second
	TimeoutExportAuditLog   = 15 * time.Second
	TimeoutTeardownVM       = 15 * time.Second
	TimeoutRevokeSVID       = 5 * time.Second
	TimeoutRevokeVaultToken = 5 * time.Second
	TimeoutVerifyCleanup    = 10 * time.Second

	HeartbeatProvisionVM = 10 * time.Second
	HeartbeatMonitorCage = 30 * time.Second
)
