package agentcage.payload.xss

deny contains msg if {
	regex.match(`(?i)\bDROP\s+(TABLE|DATABASE)`, input.payload)
	msg := "destructive SQL in XSS context"
}

deny contains msg if {
	regex.match(`(?i)<\s*form\s+.*action\s*=\s*["']https?://`, input.payload)
	msg := "phishing form injection"
}
