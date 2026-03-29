package agentcage.payload.sqli

deny contains msg if {
	regex.match(`(?i)\bDROP\s+(TABLE|DATABASE|INDEX|VIEW)`, input.payload)
	msg := "destructive SQL: DROP statement"
}

deny contains msg if {
	regex.match(`(?i)\bDELETE\s+FROM\b`, input.payload)
	msg := "destructive SQL: DELETE statement"
}

deny contains msg if {
	regex.match(`(?i)\bTRUNCATE\s+`, input.payload)
	msg := "destructive SQL: TRUNCATE statement"
}

deny contains msg if {
	regex.match(`(?i)\bUPDATE\s+\w+\s+SET\b`, input.payload)
	msg := "destructive SQL: UPDATE statement"
}

deny contains msg if {
	regex.match(`(?i)\bINSERT\s+INTO\s+(information_schema|mysql|pg_catalog|sys)`, input.payload)
	msg := "destructive SQL: INSERT into system table"
}

deny contains msg if {
	regex.match(`(?i)\bALTER\s+(TABLE|DATABASE|USER)`, input.payload)
	msg := "destructive SQL: ALTER statement"
}

deny contains msg if {
	regex.match(`(?i)\bGRANT\s+`, input.payload)
	msg := "privilege escalation: GRANT statement"
}

deny contains msg if {
	regex.match(`(?i)\bCREATE\s+(USER|ROLE)`, input.payload)
	msg := "privilege escalation: CREATE USER/ROLE"
}
