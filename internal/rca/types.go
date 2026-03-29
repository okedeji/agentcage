package rca

import "time"

type Document struct {
	ID           string
	CageID       string
	AssessmentID string
	Summary      string
	Timeline     []TimelineEntry
	RootCause    string
	Impact       string
	Remediation  string
	CreatedAt    time.Time
}

type TimelineEntry struct {
	Timestamp time.Time
	Event     string
	Details   string
}
