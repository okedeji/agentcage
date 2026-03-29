package cage

import "time"

type Type int

const (
	TypeUnspecified Type = iota
	TypeDiscovery
	TypeValidator
	TypeEscalation
)

func (t Type) String() string {
	switch t {
	case TypeDiscovery:
		return "discovery"
	case TypeValidator:
		return "validator"
	case TypeEscalation:
		return "escalation"
	default:
		return "unspecified"
	}
}

type State int

const (
	StatePending State = iota
	StateProvisioning
	StateRunning
	StatePaused
	StateTearingDown
	StateCompleted
	StateFailed
)

func (s State) String() string {
	switch s {
	case StatePending:
		return "pending"
	case StateProvisioning:
		return "provisioning"
	case StateRunning:
		return "running"
	case StatePaused:
		return "paused"
	case StateTearingDown:
		return "tearing_down"
	case StateCompleted:
		return "completed"
	case StateFailed:
		return "failed"
	default:
		return "unknown"
	}
}

type Config struct {
	AssessmentID    string
	Type            Type
	Scope           Scope
	Resources       ResourceLimits
	TimeLimits      TimeLimits
	RateLimits      RateLimits
	LLM             *LLMGatewayConfig
	ProxyConfig     ProxyConfig
	ParentFindingID string
	InputContext     []byte
}

type Scope struct {
	Hosts  []string
	Ports  []string
	Paths  []string
	Extras []string
}

type ResourceLimits struct {
	VCPUs    int32
	MemoryMB int32
}

type TimeLimits struct {
	MaxDuration time.Duration
}

type RateLimits struct {
	RequestsPerSecond int32
}

type LLMGatewayConfig struct {
	TokenBudget     int64
	RoutingStrategy string
}

type ProxyMode int

const (
	ProxyModeBlocklist ProxyMode = iota + 1
	ProxyModeClassify
	ProxyModeDisabled
)

func (m ProxyMode) String() string {
	switch m {
	case ProxyModeBlocklist:
		return "blocklist"
	case ProxyModeClassify:
		return "classify"
	case ProxyModeDisabled:
		return "disabled"
	default:
		return "unknown"
	}
}

type ProxyConfig struct {
	Mode              ProxyMode
	BlocklistPatterns []string
}

type Info struct {
	ID           string
	AssessmentID string
	Type         Type
	State        State
	Config       Config
	CreatedAt    time.Time
	UpdatedAt    time.Time
}
