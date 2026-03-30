package gateway

import (
	"errors"
	"time"
)

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

var (
	ErrBudgetExhausted = errors.New("token budget exhausted")
	ErrNoUsageData     = errors.New("LLM response missing usage data")
)

type LLMRequest struct {
	Model    string       `json:"model"`
	Messages []LLMMessage `json:"messages"`
}

type LLMMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type LLMResponse struct {
	ID      string      `json:"id"`
	Choices []LLMChoice `json:"choices"`
	Usage   LLMUsage    `json:"usage"`
	Model   string      `json:"model"`
}

type LLMChoice struct {
	Index   int        `json:"index"`
	Message LLMMessage `json:"message"`
}

type LLMUsage struct {
	PromptTokens     int64 `json:"prompt_tokens"`
	CompletionTokens int64 `json:"completion_tokens"`
	TotalTokens      int64 `json:"total_tokens"`
}
