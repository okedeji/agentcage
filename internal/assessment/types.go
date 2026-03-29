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
	StatusMapping
	StatusTesting
	StatusValidating
	StatusPendingReview
	StatusApproved
	StatusRejected
)

func (s Status) String() string {
	switch s {
	case StatusMapping:
		return "mapping"
	case StatusTesting:
		return "testing"
	case StatusValidating:
		return "validating"
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
	Scope         cage.Scope
	CageDefaults  map[cage.Type]CageTypeConfig
	TokenBudget   int64
	MaxDuration   time.Duration
	MaxChainDepth int32
	Compliance    ComplianceFramework
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
	StatusMapping:       {StatusTesting, StatusRejected},
	StatusTesting:       {StatusValidating, StatusRejected},
	StatusValidating:    {StatusPendingReview, StatusRejected},
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
