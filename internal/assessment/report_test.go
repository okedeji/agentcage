package assessment

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/okedeji/agentcage/internal/findings"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateReport_MixedSeverities(t *testing.T) {
	validated := []findings.Finding{
		{ID: "f-1", Title: "SQL Injection", Severity: findings.SeverityCritical, VulnClass: "sqli", Endpoint: "/api/users", Description: "Blind SQLi in user param"},
		{ID: "f-2", Title: "XSS Reflected", Severity: findings.SeverityHigh, VulnClass: "xss", Endpoint: "/search", Description: "Reflected XSS in search query"},
		{ID: "f-3", Title: "Info Disclosure", Severity: findings.SeverityMedium, VulnClass: "info_disclosure", Endpoint: "/debug", Description: "Stack trace in error response"},
		{ID: "f-4", Title: "Missing Header", Severity: findings.SeverityLow, VulnClass: "headers", Endpoint: "/", Description: "Missing X-Frame-Options"},
		{ID: "f-5", Title: "Server Banner", Severity: findings.SeverityInfo, VulnClass: "info", Endpoint: "/", Description: "Server version disclosed"},
	}

	report, err := GenerateReport(context.Background(), "assess-1", "cust-1", validated, "target.example.com", nil)
	require.NoError(t, err)
	require.NotNil(t, report)

	assert.Equal(t, "assess-1", report.AssessmentID)
	assert.Equal(t, "cust-1", report.CustomerID)
	assert.Equal(t, "pending_review", report.Status)
	assert.Equal(t, 5, report.Summary.TotalFindings)
	assert.Equal(t, 1, report.Summary.Critical)
	assert.Equal(t, 1, report.Summary.High)
	assert.Equal(t, 1, report.Summary.Medium)
	assert.Equal(t, 1, report.Summary.Low)
	assert.Equal(t, 1, report.Summary.Info)
	assert.Len(t, report.Findings, 5)
}

func TestGenerateReport_EmptyFindings(t *testing.T) {
	report, err := GenerateReport(context.Background(), "assess-1", "cust-1", nil, "", nil)
	require.NoError(t, err)
	require.NotNil(t, report)

	assert.Equal(t, 0, report.Summary.TotalFindings)
	assert.Equal(t, 0, report.Summary.Critical)
	assert.Equal(t, 0, report.Summary.High)
	assert.Equal(t, 0, report.Summary.Medium)
	assert.Equal(t, 0, report.Summary.Low)
	assert.Equal(t, 0, report.Summary.Info)
	assert.Empty(t, report.Findings)
}

func TestGenerateReport_FindingFieldsMapping(t *testing.T) {
	validated := []findings.Finding{
		{
			ID:          "f-1",
			Title:       "SQL Injection",
			Severity:    findings.SeverityCritical,
			VulnClass:   "sqli",
			Endpoint:    "/api/users",
			Description: "Blind SQLi",
			Evidence: findings.Evidence{
				Metadata: map[string]string{"summary": "response contained SQL error"},
			},
		},
	}

	report, err := GenerateReport(context.Background(), "assess-1", "cust-1", validated, "target.example.com", nil)
	require.NoError(t, err)

	rf := report.Findings[0]
	assert.Equal(t, "f-1", rf.ID)
	assert.Equal(t, "SQL Injection", rf.Title)
	assert.Equal(t, "critical", rf.Severity)
	assert.Equal(t, "sqli", rf.VulnClass)
	assert.Equal(t, "/api/users", rf.Endpoint)
	assert.Equal(t, "Blind SQLi", rf.Description)
	assert.Equal(t, "response contained SQL error", rf.Evidence)
}

func TestGenerateReport_MissingAssessmentID(t *testing.T) {
	_, err := GenerateReport(context.Background(), "", "cust-1", nil, "", nil)
	assert.Error(t, err)
}

func TestGenerateReport_MissingCustomerID(t *testing.T) {
	_, err := GenerateReport(context.Background(), "assess-1", "", nil, "", nil)
	assert.Error(t, err)
}

func TestFormatJSON_ValidOutput(t *testing.T) {
	report := &Report{
		AssessmentID: "assess-1",
		CustomerID:   "cust-1",
		Status:       "pending_review",
		Summary:      ReportSummary{TotalFindings: 1, Critical: 1},
		Findings: []ReportFinding{
			{ID: "f-1", Title: "SQLi", Severity: "critical"},
		},
	}

	data, err := FormatJSON(report)
	require.NoError(t, err)

	var parsed Report
	err = json.Unmarshal(data, &parsed)
	require.NoError(t, err)

	assert.Equal(t, "assess-1", parsed.AssessmentID)
	assert.Equal(t, 1, parsed.Summary.Critical)
	assert.Len(t, parsed.Findings, 1)
}
