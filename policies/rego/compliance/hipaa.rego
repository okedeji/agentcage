package agentcage.compliance.hipaa

deny contains msg if {
	not input.data_redaction_enabled
	msg := "HIPAA: data redaction must be enabled for PHI-containing targets"
}

deny contains msg if {
	not input.audit_log_enabled
	msg := "HIPAA: audit logging must be enabled"
}

deny contains msg if {
	input.max_concurrent_cages > 200
	msg := sprintf("HIPAA: maximum concurrent cages is 200, got %d", [input.max_concurrent_cages])
}

deny contains msg if {
	not input.encryption_at_rest
	msg := "HIPAA: encryption at rest must be enabled"
}

deny contains msg if {
	not input.intervention_enabled
	msg := "HIPAA: human intervention must be enabled"
}
