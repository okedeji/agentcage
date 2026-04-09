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
	CustomerID       string
	Name             string
	BundleRef        string
	Target           cage.Scope
	Exclude          ExcludeConfig
	CageDefaults     map[cage.Type]CageTypeConfig
	TokenBudget      int64
	MaxDuration      time.Duration
	MaxChainDepth    int32
	MaxConcurrent    int32
	Compliance       []ComplianceFramework
	Guidance         *Guidance
	Tags             map[string]string
	Notifications    NotificationConfig
}

type ExcludeConfig struct {
	Hosts []string
	Paths []string
}

// Cage creation uses this instead of Config.Target so excluded
// hosts and paths never reach a cage.
func (c Config) FilteredScope() cage.Scope {
	if len(c.Exclude.Hosts) == 0 && len(c.Exclude.Paths) == 0 {
		return c.Target
	}
	excludeHost := make(map[string]bool, len(c.Exclude.Hosts))
	for _, h := range c.Exclude.Hosts {
		excludeHost[h] = true
	}
	excludePath := make(map[string]bool, len(c.Exclude.Paths))
	for _, p := range c.Exclude.Paths {
		excludePath[p] = true
	}
	out := cage.Scope{Extras: c.Target.Extras}
	for _, h := range c.Target.Hosts {
		if !excludeHost[h] {
			out.Hosts = append(out.Hosts, h)
		}
	}
	for _, p := range c.Target.Paths {
		if !excludePath[p] {
			out.Paths = append(out.Paths, p)
		}
	}
	out.Ports = c.Target.Ports
	return out
}

type NotificationConfig struct {
	Webhook    string
	OnFinding  bool
	OnComplete bool
}

type Guidance struct {
	AttackSurface  *AttackSurfaceGuidance  `json:"attack_surface,omitempty"`
	Priorities     *PrioritiesGuidance     `json:"priorities,omitempty"`
	AttackStrategy *AttackStrategyGuidance `json:"attack_strategy,omitempty"`
	Validation     *ValidationGuidance     `json:"validation,omitempty"`
}

type AttackSurfaceGuidance struct {
	Endpoints     []string `json:"endpoints,omitempty"`
	APISpecs      []string `json:"api_specs,omitempty"`
	LimitToListed bool     `json:"limit_to_listed,omitempty"`
}

type PrioritiesGuidance struct {
	VulnClasses []string `json:"vuln_classes,omitempty"`
	SkipPaths   []string `json:"skip_paths,omitempty"`
}

type AttackStrategyGuidance struct {
	KnownWeaknesses []string `json:"known_weaknesses,omitempty"`
	Context         string   `json:"context,omitempty"`
}

type ValidationGuidance struct {
	RequirePoC         bool `json:"require_poc,omitempty"`
	HeadlessBrowserXSS bool `json:"headless_browser_xss,omitempty"`
}

type CageTypeConfig struct {
	Type          cage.Type
	Resources     cage.ResourceLimits
	MaxConcurrent int32
	MaxDuration   time.Duration
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
