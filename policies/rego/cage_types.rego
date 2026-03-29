package agentcage.cage_types

deny contains msg if {
	input.cage_type == "validator"
	input.llm_config != null
	msg := "validator cages must not have LLM access"
}

deny contains msg if {
	input.cage_type == "validator"
	input.time_limit_seconds > 60
	msg := sprintf("validator cage time limit cannot exceed 60 seconds, got %d", [input.time_limit_seconds])
}

deny contains msg if {
	input.cage_type == "validator"
	input.resources.vcpus > 1
	msg := sprintf("validator cage cannot exceed 1 vCPU, got %d", [input.resources.vcpus])
}

deny contains msg if {
	input.cage_type == "validator"
	input.resources.memory_mb > 1024
	msg := sprintf("validator cage cannot exceed 1024 MB RAM, got %d", [input.resources.memory_mb])
}

deny contains msg if {
	input.cage_type == "validator"
	input.parent_finding_id == ""
	msg := "validator cages require a parent finding ID"
}

deny contains msg if {
	input.cage_type == "discovery"
	input.llm_config == null
	msg := "discovery cages require LLM gateway configuration"
}

deny contains msg if {
	input.cage_type == "discovery"
	input.time_limit_seconds > 1800
	msg := sprintf("discovery cage time limit cannot exceed 1800 seconds, got %d", [input.time_limit_seconds])
}

deny contains msg if {
	input.cage_type == "discovery"
	input.resources.vcpus > 4
	msg := sprintf("discovery cage cannot exceed 4 vCPUs, got %d", [input.resources.vcpus])
}

deny contains msg if {
	input.cage_type == "discovery"
	input.resources.memory_mb > 8192
	msg := sprintf("discovery cage cannot exceed 8192 MB RAM, got %d", [input.resources.memory_mb])
}

deny contains msg if {
	input.cage_type == "escalation"
	input.parent_finding_id == ""
	msg := "escalation cages require a confirmed finding as input"
}

deny contains msg if {
	input.cage_type == "escalation"
	input.time_limit_seconds > 900
	msg := sprintf("escalation cage time limit cannot exceed 900 seconds, got %d", [input.time_limit_seconds])
}

deny contains msg if {
	input.cage_type == "escalation"
	input.resources.vcpus > 2
	msg := sprintf("escalation cage cannot exceed 2 vCPUs, got %d", [input.resources.vcpus])
}

deny contains msg if {
	input.rate_limit_rps <= 0
	msg := "rate limit must be positive"
}

deny contains msg if {
	input.rate_limit_rps > 1000
	msg := sprintf("rate limit cannot exceed 1000 req/s, got %d", [input.rate_limit_rps])
}
