package gateway

import "time"

type RoutingStrategy int

const (
	StrategyCostOptimized RoutingStrategy = iota + 1
	StrategyQualityFirst
	StrategyLatencyFirst
)

func (s RoutingStrategy) String() string {
	switch s {
	case StrategyCostOptimized:
		return "cost_optimized"
	case StrategyQualityFirst:
		return "quality_first"
	case StrategyLatencyFirst:
		return "latency_first"
	default:
		return "unknown"
	}
}

type ProviderConfig struct {
	Name     string
	Endpoint string
	Models   []string
	Priority int
	Timeout  time.Duration
}

type TokenUsage struct {
	CageID       string
	AssessmentID string
	Provider     string
	Model        string
	InputTokens  int64
	OutputTokens int64
	Timestamp    time.Time
}

type BudgetStatus struct {
	CageID         string
	AssessmentID   string
	TokenBudget    int64
	TokensConsumed int64
	Exhausted      bool
}
