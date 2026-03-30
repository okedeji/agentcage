package rca

import (
	"strings"
	"time"

	"github.com/google/uuid"
)

func Generate(cageID, assessmentID, failureReason string, timeline []TimelineEntry) Document {
	return Document{
		ID:           uuid.NewString(),
		CageID:       cageID,
		AssessmentID: assessmentID,
		Summary:      failureReason,
		Timeline:     timeline,
		RootCause:    failureReason,
		Impact:       classifyImpact(failureReason),
		Remediation:  suggestRemediation(failureReason),
		CreatedAt:    time.Now(),
	}
}

func classifyImpact(reason string) string {
	r := strings.ToLower(reason)
	switch {
	case strings.Contains(r, "timeout"):
		return "Cage exceeded time limit. Partial findings may have been emitted before termination."
	case strings.Contains(r, "tripwire"):
		return "Cage terminated due to behavioral anomaly. All findings emitted before the tripwire are preserved."
	case strings.Contains(r, "budget") || strings.Contains(r, "token"):
		return "Cage exhausted its LLM token budget. Findings emitted before exhaustion are preserved."
	case strings.Contains(r, "provision"):
		return "Cage failed to provision. No findings were emitted."
	default:
		return "Cage failed during execution. Partial findings may have been emitted."
	}
}

func suggestRemediation(reason string) string {
	r := strings.ToLower(reason)
	switch {
	case strings.Contains(r, "timeout"):
		return "Consider increasing the time limit for this cage type, or narrowing the task scope."
	case strings.Contains(r, "tripwire"):
		return "Review the Falco alert details in the audit log. Adjust tripwire sensitivity or cage type if the behavior was expected."
	case strings.Contains(r, "budget") || strings.Contains(r, "token"):
		return "Consider increasing the token budget, or switching to a more cost-efficient routing strategy."
	case strings.Contains(r, "provision"):
		return "Check host capacity and Firecracker configuration. Verify the cage image is available."
	default:
		return "Review the audit log timeline for the failure sequence."
	}
}
