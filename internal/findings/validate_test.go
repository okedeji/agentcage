package findings

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func validFinding() Finding {
	return Finding{
		ID:           "f-001",
		AssessmentID: "a-001",
		CageID:       "c-001",
		Status:       StatusCandidate,
		Severity:     SeverityHigh,
		Title:        "SQL Injection in /api/users",
		Description:  "The endpoint is vulnerable to SQL injection via the id parameter.",
		VulnClass:    "sqli",
		Endpoint:     "https://target.example.com/api/users",
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}
}

func TestValidateFinding_Valid(t *testing.T) {
	err := ValidateFinding(validFinding())
	assert.NoError(t, err)
}

func TestValidateFinding_MissingFields(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Finding)
		want   string
	}{
		{"missing ID", func(f *Finding) { f.ID = "" }, "ID"},
		{"missing AssessmentID", func(f *Finding) { f.AssessmentID = "" }, "AssessmentID"},
		{"missing CageID", func(f *Finding) { f.CageID = "" }, "CageID"},
		{"missing Title", func(f *Finding) { f.Title = "" }, "Title"},
		{"missing VulnClass", func(f *Finding) { f.VulnClass = "" }, "VulnClass"},
		{"zero Status", func(f *Finding) { f.Status = 0 }, "status"},
		{"zero Severity", func(f *Finding) { f.Severity = 0 }, "severity"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := validFinding()
			tt.mutate(&f)
			err := ValidateFinding(f)
			require.Error(t, err)
			assert.True(t, errors.Is(err, ErrInvalidFinding))
			assert.Contains(t, err.Error(), tt.want)
		})
	}
}

func TestValidateFinding_MultipleViolations(t *testing.T) {
	f := Finding{}
	err := ValidateFinding(f)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidFinding))
	assert.Contains(t, err.Error(), "ID")
	assert.Contains(t, err.Error(), "AssessmentID")
	assert.Contains(t, err.Error(), "CageID")
	assert.Contains(t, err.Error(), "Title")
	assert.Contains(t, err.Error(), "VulnClass")
	assert.Contains(t, err.Error(), "status")
	assert.Contains(t, err.Error(), "severity")
}

func TestSanitizeFinding_Truncates(t *testing.T) {
	f := validFinding()
	f.Title = strings.Repeat("a", 1000)
	f.Description = strings.Repeat("b", 20000)
	f.Evidence.Request = make([]byte, 2<<20)
	f.Evidence.Response = make([]byte, 2<<20)
	f.Evidence.Screenshot = make([]byte, 10<<20)

	SanitizeFinding(&f)

	assert.Len(t, f.Title, maxTitleLength)
	assert.Len(t, f.Description, maxDescriptionLength)
	assert.Len(t, f.Evidence.Request, maxEvidenceRequestSize)
	assert.Len(t, f.Evidence.Response, maxEvidenceResponseSize)
	assert.Len(t, f.Evidence.Screenshot, maxEvidenceScreenshotSize)
}

func TestSanitizeFinding_LeavesNormalUnchanged(t *testing.T) {
	f := validFinding()
	f.Evidence.Request = []byte("GET /api/users HTTP/1.1")
	f.Evidence.Response = []byte("HTTP/1.1 200 OK")

	origTitle := f.Title
	origDesc := f.Description
	origReqLen := len(f.Evidence.Request)
	origRespLen := len(f.Evidence.Response)

	SanitizeFinding(&f)

	assert.Equal(t, origTitle, f.Title)
	assert.Equal(t, origDesc, f.Description)
	assert.Len(t, f.Evidence.Request, origReqLen)
	assert.Len(t, f.Evidence.Response, origRespLen)
}
