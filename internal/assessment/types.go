package assessment

import (
	"errors"
	"fmt"
	"time"

	"github.com/okedeji/agentcage/internal/cage"
)

type Status int

const (
	StatusUnspecified Status = iota
	StatusDiscovery
	StatusExploitation
	StatusValidation
	StatusPendingReview
	StatusApproved
	StatusRejected
)

func (s Status) String() string {
	switch s {
	case StatusDiscovery:
		return "discovery"
	case StatusExploitation:
		return "exploitation"
	case StatusValidation:
		return "validation"
	case StatusPendingReview:
		return "pending_review"
	case StatusApproved:
		return "approved"
	case StatusRejected:
		return "rejected"
	default:
		return "unspecified"
	}
}

func StatusFromString(s string) Status {
	switch s {
	case "discovery":
		return StatusDiscovery
	case "exploitation":
		return StatusExploitation
	case "validation":
		return StatusValidation
	case "pending_review":
		return StatusPendingReview
	case "approved":
		return StatusApproved
	case "rejected":
		return StatusRejected
	default:
		return StatusUnspecified
	}
}

type ComplianceFramework int

const (
	ComplianceUnspecified ComplianceFramework = iota
	ComplianceSOC2
	ComplianceHIPAA
	CompliancePCIDSS
)

func (f ComplianceFramework) String() string {
	switch f {
	case ComplianceSOC2:
		return "soc2"
	case ComplianceHIPAA:
		return "hipaa"
	case CompliancePCIDSS:
		return "pci_dss"
	default:
		return "unspecified"
	}
}

type Config struct {
	CustomerID    string
	Target        cage.Scope
	CageDefaults  map[cage.Type]CageTypeConfig
	TokenBudget   int64
	MaxDuration   time.Duration
	MaxChainDepth int32
	Compliance    ComplianceFramework
	Guidance      *Guidance
}

// Guidance is optional practitioner context that shapes how agentcage
// discovers, prioritizes, attacks, and validates. Matches the four
// dimensions of a pentest methodology.
type Guidance struct {
	AttackSurface  *AttackSurfaceGuidance  `json:"attack_surface,omitempty"`
	Priorities     *PrioritiesGuidance     `json:"priorities,omitempty"`
	AttackStrategy *AttackStrategyGuidance `json:"attack_strategy,omitempty"`
	Validation     *ValidationGuidance     `json:"validation,omitempty"`
}

// AttackSurfaceGuidance narrows or expands what the coordinator discovers.
type AttackSurfaceGuidance struct {
	Endpoints     []string `json:"endpoints,omitempty"`
	APISpecs      []string `json:"api_specs,omitempty"`
	LimitToListed bool     `json:"limit_to_listed,omitempty"`
}

// PrioritiesGuidance focuses testing on high-value areas.
type PrioritiesGuidance struct {
	Focus        []string `json:"focus,omitempty"`
	Deprioritize []string `json:"deprioritize,omitempty"`
	VulnClasses  []string `json:"vuln_classes,omitempty"`
}

// AttackStrategyGuidance provides exploit knowledge and payload hints.
type AttackStrategyGuidance struct {
	VulnClasses    []string `json:"vuln_classes,omitempty"`
	KnownWeaknesses []string `json:"known_weaknesses,omitempty"`
	Context        string   `json:"context,omitempty"`
}

// ValidationGuidance controls how findings are confirmed.
type ValidationGuidance struct {
	RequirePoC         bool `json:"require_poc,omitempty"`
	HeadlessBrowserXSS bool `json:"headless_browser_xss,omitempty"`
}

type CageTypeConfig struct {
	Type          cage.Type
	Resources     cage.ResourceLimits
	MaxConcurrent int32
}

type Info struct {
	ID         string
	CustomerID string
	Status     Status
	Config     Config
	Stats      Stats
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

type Stats struct {
	TotalCages        int32
	ActiveCages       int32
	FindingsCandidate int32
	FindingsValidated int32
	FindingsRejected  int32
	TokensConsumed    int64
}

var validTransitions = map[Status][]Status{
	StatusDiscovery:     {StatusExploitation, StatusRejected},
	StatusExploitation:  {StatusValidation, StatusRejected},
	StatusValidation:    {StatusPendingReview, StatusRejected},
	StatusPendingReview: {StatusApproved, StatusRejected},
}

var ErrInvalidTransition = errors.New("invalid assessment state transition")

func ValidateTransition(from, to Status) error {
	allowed, ok := validTransitions[from]
	if !ok {
		return fmt.Errorf("%w: no transitions from %s", ErrInvalidTransition, from)
	}
	for _, s := range allowed {
		if s == to {
			return nil
		}
	}
	return fmt.Errorf("%w: %s to %s", ErrInvalidTransition, from, to)
}
