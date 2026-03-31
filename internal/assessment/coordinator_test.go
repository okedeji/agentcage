package assessment

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/okedeji/agentcage/internal/cage"
	"github.com/okedeji/agentcage/internal/findings"
)

func TestSummarizeFindings(t *testing.T) {
	ff := []findings.Finding{
		{
			ID:         "f-1",
			Title:      "SQL Injection in /api/login",
			Severity:   findings.SeverityHigh,
			VulnClass:  "sqli",
			Endpoint:   "/api/login",
			Status:     findings.StatusCandidate,
			ChainDepth: 0,
		},
		{
			ID:         "f-2",
			Title:      "XSS in /search",
			Severity:   findings.SeverityMedium,
			VulnClass:  "xss",
			Endpoint:   "/search",
			Status:     findings.StatusValidated,
			ChainDepth: 1,
		},
	}

	summaries := SummarizeFindings(ff)
	assert.Len(t, summaries, 2)

	assert.Equal(t, "f-1", summaries[0].ID)
	assert.Equal(t, "SQL Injection in /api/login", summaries[0].Title)
	assert.Equal(t, "high", summaries[0].Severity)
	assert.Equal(t, "sqli", summaries[0].VulnClass)
	assert.Equal(t, "candidate", summaries[0].Status)

	assert.Equal(t, "f-2", summaries[1].ID)
	assert.Equal(t, "validated", summaries[1].Status)
	assert.Equal(t, int32(1), summaries[1].ChainDepth)
}

func TestUpdateCoverage(t *testing.T) {
	coverage := make(map[string][]string)

	actions := []CoordinatorAction{
		{Scope: cage.Scope{Hosts: []string{"target.com"}}, VulnClass: "sqli"},
		{Scope: cage.Scope{Hosts: []string{"target.com"}}, VulnClass: "xss"},
		{Scope: cage.Scope{Hosts: []string{"api.target.com"}}, VulnClass: "sqli"},
	}

	coverage = UpdateCoverage(coverage, actions)

	assert.Contains(t, coverage["target.com"], "sqli")
	assert.Contains(t, coverage["target.com"], "xss")
	assert.Contains(t, coverage["api.target.com"], "sqli")
	assert.Len(t, coverage["target.com"], 2)
}

func TestUpdateCoverage_NoDuplicates(t *testing.T) {
	coverage := map[string][]string{
		"target.com": {"sqli"},
	}

	actions := []CoordinatorAction{
		{Scope: cage.Scope{Hosts: []string{"target.com"}}, VulnClass: "sqli"},
		{Scope: cage.Scope{Hosts: []string{"target.com"}}, VulnClass: "xss"},
	}

	coverage = UpdateCoverage(coverage, actions)

	// sqli should not be duplicated
	sqliCount := 0
	for _, v := range coverage["target.com"] {
		if v == "sqli" {
			sqliCount++
		}
	}
	assert.Equal(t, 1, sqliCount)
	assert.Contains(t, coverage["target.com"], "xss")
}

func TestUpdateCoverage_NilInput(t *testing.T) {
	coverage := UpdateCoverage(nil, []CoordinatorAction{
		{Scope: cage.Scope{Hosts: []string{"x.com"}}, VulnClass: "rce"},
	})
	assert.Contains(t, coverage["x.com"], "rce")
}

func TestUpdateCoverage_EmptyVulnClass(t *testing.T) {
	coverage := make(map[string][]string)
	coverage = UpdateCoverage(coverage, []CoordinatorAction{
		{Scope: cage.Scope{Hosts: []string{"x.com"}}, VulnClass: ""},
	})
	assert.Empty(t, coverage["x.com"])
}
