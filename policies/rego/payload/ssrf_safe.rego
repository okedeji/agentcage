package agentcage.payload.ssrf

deny contains msg if {
	regex.match(`(?i)(^|=)https?://(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)`, input.payload)
	msg := "SSRF to private IP range"
}

deny contains msg if {
	regex.match(`(?i)(^|=)https?://127\.`, input.payload)
	msg := "SSRF to loopback"
}

deny contains msg if {
	regex.match(`(?i)(^|=)https?://localhost`, input.payload)
	msg := "SSRF to localhost"
}

deny contains msg if {
	regex.match(`(?i)(^|=)https?://\[::1\]`, input.payload)
	msg := "SSRF to IPv6 loopback"
}

deny contains msg if {
	regex.match(`(?i)(^|=)https?://169\.254\.169\.254`, input.payload)
	msg := "SSRF to cloud metadata endpoint"
}

deny contains msg if {
	regex.match(`(?i)(^|=)https?://metadata\.google\.internal`, input.payload)
	msg := "SSRF to GCP metadata"
}
