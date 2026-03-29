package agentcage.compliance.soc2

deny contains msg if {
	input.max_concurrent_cages > 500
	msg := sprintf("SOC2: maximum concurrent cages is 500, got %d", [input.max_concurrent_cages])
}

deny contains msg if {
	not input.audit_log_enabled
	msg := "SOC2: audit logging must be enabled"
}

deny contains msg if {
	not input.intervention_enabled
	msg := "SOC2: human intervention must be enabled"
}

deny contains msg if {
	input.intervention_timeout_minutes > 30
	msg := sprintf("SOC2: intervention timeout cannot exceed 30 minutes, got %d", [input.intervention_timeout_minutes])
}
