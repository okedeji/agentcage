package findings

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSubject(t *testing.T) {
	assert.Equal(t, "assessment.a-001.findings", Subject("a-001"))
}

func TestDeadLetterSubject(t *testing.T) {
	assert.Equal(t, "assessment.a-001.findings.dead", DeadLetterSubject("a-001"))
}

func TestStreamName(t *testing.T) {
	assert.Equal(t, "findings-a-001", streamName("a-001"))
}

func TestMessageMarshalRoundTrip(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	original := Message{
		SchemaVersion: SchemaVersionV1,
		Finding: Finding{
			ID:           "f-001",
			AssessmentID: "a-001",
			CageID:       "c-001",
			Status:       StatusCandidate,
			Severity:     SeverityHigh,
			Title:        "SQL Injection in /api/users",
			Description:  "The endpoint is vulnerable.",
			VulnClass:    "sqli",
			Endpoint:     "https://target.example.com/api/users",
			Evidence: Evidence{
				Request:  []byte("GET /api/users?id=1' OR 1=1"),
				Response: []byte("HTTP/1.1 500 Internal Server Error"),
				Metadata: map[string]string{"tool": "sqlmap"},
			},
			ParentFindingID: "",
			ChainDepth:      0,
			CreatedAt:       now,
			UpdatedAt:       now,
		},
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded Message
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.SchemaVersion, decoded.SchemaVersion)
	assert.Equal(t, original.Finding.ID, decoded.Finding.ID)
	assert.Equal(t, original.Finding.AssessmentID, decoded.Finding.AssessmentID)
	assert.Equal(t, original.Finding.CageID, decoded.Finding.CageID)
	assert.Equal(t, original.Finding.Title, decoded.Finding.Title)
	assert.Equal(t, original.Finding.VulnClass, decoded.Finding.VulnClass)
	assert.Equal(t, original.Finding.Evidence.Request, decoded.Finding.Evidence.Request)
	assert.Equal(t, original.Finding.Evidence.Response, decoded.Finding.Evidence.Response)
	assert.Equal(t, original.Finding.Evidence.Metadata, decoded.Finding.Evidence.Metadata)
}

func TestMessageMarshalProducesValidJSON(t *testing.T) {
	validated := time.Now()
	msg := Message{
		SchemaVersion: SchemaVersionV1,
		Finding: Finding{
			ID:              "f-002",
			AssessmentID:    "a-002",
			CageID:          "c-002",
			Status:          StatusValidated,
			Severity:        SeverityCritical,
			Title:           "RCE via deserialization",
			Description:     "Java deserialization leads to remote code execution.",
			VulnClass:       "rce",
			Endpoint:        "https://target.example.com/api/upload",
			ParentFindingID: "f-001",
			ChainDepth:      1,
			CreatedAt:       time.Now(),
			UpdatedAt:       time.Now(),
			ValidatedAt:     &validated,
			Evidence: Evidence{
				Request:    []byte("POST /api/upload"),
				Response:   []byte("HTTP/1.1 200 OK"),
				Screenshot: []byte{0x89, 0x50, 0x4E, 0x47},
				Metadata:   map[string]string{"chain": "sqli->rce"},
			},
		},
	}

	data, err := json.Marshal(msg)
	require.NoError(t, err)
	assert.True(t, json.Valid(data))
}

func TestNewNATSBus_InvalidURL(t *testing.T) {
	_, err := NewNATSBus("nats://localhost:1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "connecting to NATS")
}
