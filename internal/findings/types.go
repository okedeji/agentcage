package findings

import (
	"encoding/json"
	"fmt"
	"time"
)

type Status int

const (
	StatusCandidate Status = iota + 1
	StatusValidated
	StatusRejected
)

func (s Status) String() string {
	switch s {
	case StatusCandidate:
		return "candidate"
	case StatusValidated:
		return "validated"
	case StatusRejected:
		return "rejected"
	default:
		return "unknown"
	}
}

func (s Status) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.String())
}

func (s *Status) UnmarshalJSON(data []byte) error {
	var v any
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}
	switch val := v.(type) {
	case string:
		*s = ParseStatus(val)
		if *s == 0 {
			return fmt.Errorf("unknown finding status: %q", val)
		}
	case float64:
		*s = Status(int(val))
	default:
		return fmt.Errorf("invalid finding status type: %T", v)
	}
	return nil
}

func ParseStatus(s string) Status {
	switch s {
	case "candidate":
		return StatusCandidate
	case "validated":
		return StatusValidated
	case "rejected":
		return StatusRejected
	default:
		return 0
	}
}

type Severity int

const (
	SeverityInfo Severity = iota + 1
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

func (s Severity) String() string {
	switch s {
	case SeverityInfo:
		return "info"
	case SeverityLow:
		return "low"
	case SeverityMedium:
		return "medium"
	case SeverityHigh:
		return "high"
	case SeverityCritical:
		return "critical"
	default:
		return "unknown"
	}
}

func (s Severity) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.String())
}

func (s *Severity) UnmarshalJSON(data []byte) error {
	var v any
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}
	switch val := v.(type) {
	case string:
		*s = ParseSeverity(val)
		if *s == 0 {
			return fmt.Errorf("unknown finding severity: %q", val)
		}
	case float64:
		*s = Severity(int(val))
	default:
		return fmt.Errorf("invalid finding severity type: %T", v)
	}
	return nil
}

func ParseSeverity(s string) Severity {
	switch s {
	case "info":
		return SeverityInfo
	case "low":
		return SeverityLow
	case "medium":
		return SeverityMedium
	case "high":
		return SeverityHigh
	case "critical":
		return SeverityCritical
	default:
		return 0
	}
}

type Finding struct {
	ID              string     `json:"id"`
	AssessmentID    string     `json:"assessment_id"`
	CageID          string     `json:"cage_id"`
	Status          Status     `json:"status"`
	Severity        Severity   `json:"severity"`
	Title           string     `json:"title"`
	Description     string     `json:"description,omitempty"`
	VulnClass       string     `json:"vuln_class"`
	Endpoint        string     `json:"endpoint"`
	Evidence        Evidence   `json:"evidence,omitempty"`
	ParentFindingID string     `json:"parent_finding_id,omitempty"`
	ChainDepth      int32      `json:"chain_depth,omitempty"`
	CWE             string     `json:"cwe,omitempty"`
	CVSSScore       float64    `json:"cvss_score,omitempty"`
	Remediation     string     `json:"remediation,omitempty"`
	ValidationProof *Proof     `json:"validation_proof,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
	ValidatedAt     *time.Time `json:"validated_at,omitempty"`
}

type Evidence struct {
	Request    []byte            `json:"request,omitempty"`
	Response   []byte            `json:"response,omitempty"`
	Screenshot []byte            `json:"screenshot,omitempty"`
	PoC        string            `json:"poc,omitempty"`
	Metadata   map[string]string `json:"metadata,omitempty"`
}

type Proof struct {
	ReproductionSteps string `json:"reproduction_steps"`
	Confirmed         bool   `json:"confirmed"`
	Deterministic     bool   `json:"deterministic"`
	ValidatorCageID   string `json:"validator_cage_id"`
	Evidence          string `json:"evidence,omitempty"`
}
