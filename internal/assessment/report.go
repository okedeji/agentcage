package assessment

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/okedeji/agentcage/internal/findings"
)

type Report struct {
	AssessmentID  string          `json:"assessment_id"`
	CustomerID    string          `json:"customer_id"`
	GeneratedAt   time.Time       `json:"generated_at"`
	Status        string          `json:"status"`
	Summary       ReportSummary   `json:"summary"`
	Findings      []ReportFinding `json:"findings"`
	AuditDigestID string          `json:"audit_digest_id,omitempty"`
}

type ReportSummary struct {
	TotalFindings int `json:"total_findings"`
	Critical      int `json:"critical"`
	High          int `json:"high"`
	Medium        int `json:"medium"`
	Low           int `json:"low"`
	Info          int `json:"info"`
}

type ReportFinding struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Severity    string `json:"severity"`
	VulnClass   string `json:"vuln_class"`
	Endpoint    string `json:"endpoint"`
	Description string `json:"description"`
	Evidence    string `json:"evidence,omitempty"`
	Remediation string `json:"remediation,omitempty"`
}

func GenerateReport(assessmentID, customerID string, validated []findings.Finding) (*Report, error) {
	if assessmentID == "" {
		return nil, fmt.Errorf("generating report: assessment ID is required")
	}
	if customerID == "" {
		return nil, fmt.Errorf("generating report: customer ID is required")
	}

	summary := ReportSummary{TotalFindings: len(validated)}
	reportFindings := make([]ReportFinding, 0, len(validated))

	for _, f := range validated {
		switch f.Severity {
		case findings.SeverityCritical:
			summary.Critical++
		case findings.SeverityHigh:
			summary.High++
		case findings.SeverityMedium:
			summary.Medium++
		case findings.SeverityLow:
			summary.Low++
		case findings.SeverityInfo:
			summary.Info++
		}

		var evidence string
		if meta := f.Evidence.Metadata; meta != nil {
			if v, ok := meta["summary"]; ok {
				evidence = v
			}
		}

		reportFindings = append(reportFindings, ReportFinding{
			ID:          f.ID,
			Title:       f.Title,
			Severity:    f.Severity.String(),
			VulnClass:   f.VulnClass,
			Endpoint:    f.Endpoint,
			Description: f.Description,
			Evidence:    evidence,
		})
	}

	return &Report{
		AssessmentID: assessmentID,
		CustomerID:   customerID,
		GeneratedAt:  time.Now(),
		Status:       StatusPendingReview.String(),
		Summary:      summary,
		Findings:     reportFindings,
	}, nil
}

func FormatJSON(report *Report) ([]byte, error) {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("formatting report as JSON: %w", err)
	}
	return data, nil
}
