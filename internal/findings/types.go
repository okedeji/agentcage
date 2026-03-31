package findings

import "time"

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

type Finding struct {
	ID              string
	AssessmentID    string
	CageID          string
	Status          Status
	Severity        Severity
	Title           string
	Description     string
	VulnClass       string
	Endpoint        string
	Evidence        Evidence
	ParentFindingID string
	ChainDepth      int32
	CreatedAt       time.Time
	UpdatedAt       time.Time
	ValidatedAt     *time.Time
}

type Evidence struct {
	Request    []byte
	Response   []byte
	Screenshot []byte
	PoC        string
	Metadata   map[string]string
}
