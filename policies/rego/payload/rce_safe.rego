package agentcage.payload.rce

deny contains msg if {
	regex.match(`(?i)\brm\s+-rf\b`, input.payload)
	msg := "destructive command: rm -rf"
}

deny contains msg if {
	regex.match(`(?i)\bmkfs\b`, input.payload)
	msg := "destructive command: mkfs"
}

deny contains msg if {
	regex.match(`(?i)\bdd\s+`, input.payload)
	msg := "destructive command: dd"
}

deny contains msg if {
	regex.match(`(?i)\bshutdown\b`, input.payload)
	msg := "destructive command: shutdown"
}

deny contains msg if {
	regex.match(`(?i)\breboot\b`, input.payload)
	msg := "destructive command: reboot"
}

deny contains msg if {
	regex.match(`:\(\)\s*\{\s*:\|\s*:&\s*\}\s*;`, input.payload)
	msg := "fork bomb"
}

deny contains msg if {
	regex.match(`(?i)\bchmod\s+[0-7]*777\b`, input.payload)
	msg := "dangerous permission change"
}

deny contains msg if {
	regex.match(`(?i)\bchown\s+root\b`, input.payload)
	msg := "ownership change to root"
}

deny contains msg if {
	regex.match(`(?i)>\s*/etc/(passwd|shadow|sudoers)`, input.payload)
	msg := "write to sensitive system file"
}

deny contains msg if {
	regex.match(`(?i)\bcurl\s+.*\|\s*(bash|sh)`, input.payload)
	msg := "remote code download and execute"
}

deny contains msg if {
	regex.match(`(?i)\bwget\s+.*\|\s*(bash|sh)`, input.payload)
	msg := "remote code download and execute"
}
