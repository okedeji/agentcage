package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	CageTypes         map[string]CageTypeConfig  `yaml:"cage_types"`
	RateLimits        RateLimitsConfig           `yaml:"rate_limits"`
	ActivityTimeouts  ActivityTimeoutsConfig     `yaml:"activity_timeouts"`
	FalcoRules        map[string][]FalcoRule     `yaml:"falco_rules"`
	TripwirePolicies  map[string]TripwireConfig  `yaml:"tripwire_policies"`
	BlocklistPatterns map[string][]PatternEntry  `yaml:"blocklist_patterns"`
	Infrastructure    InfrastructureConfig       `yaml:"infrastructure"`
}

type FalcoRule struct {
	Rule      string   `yaml:"rule"`
	Desc      string   `yaml:"desc"`
	Condition string   `yaml:"condition"`
	Output    string   `yaml:"output"`
	Priority  string   `yaml:"priority"`
	Tags      []string `yaml:"tags"`
}

type CageTypeConfig struct {
	MaxDuration time.Duration `yaml:"max_duration"`
	MaxVCPUs    int32         `yaml:"max_vcpus"`
	MaxMemoryMB int32         `yaml:"max_memory_mb"`
}

type RateLimitsConfig struct {
	MaxRequestsPerSecond int32 `yaml:"max_requests_per_second"`
}

type ActivityTimeoutsConfig struct {
	ValidateScope        time.Duration `yaml:"validate_scope"`
	IssueIdentity        time.Duration `yaml:"issue_identity"`
	FetchSecrets         time.Duration `yaml:"fetch_secrets"`
	ProvisionVM          time.Duration `yaml:"provision_vm"`
	ApplyPolicy          time.Duration `yaml:"apply_policy"`
	StartAgent           time.Duration `yaml:"start_agent"`
	ExportAuditLog       time.Duration `yaml:"export_audit_log"`
	TeardownVM           time.Duration `yaml:"teardown_vm"`
	RevokeSVID           time.Duration `yaml:"revoke_svid"`
	RevokeVaultToken     time.Duration `yaml:"revoke_vault_token"`
	VerifyCleanup        time.Duration `yaml:"verify_cleanup"`
	HeartbeatProvisionVM time.Duration `yaml:"heartbeat_provision_vm"`
	HeartbeatMonitorCage time.Duration `yaml:"heartbeat_monitor_cage"`
}

type TripwireConfig struct {
	Default string            `yaml:"default"`
	Rules   map[string]string `yaml:"rules"`
}

type PatternEntry struct {
	Pattern string `yaml:"pattern"`
	Message string `yaml:"message"`
}

type InfrastructureConfig struct {
	LLMEndpoint              string        `yaml:"llm_endpoint"`
	LLMTimeout               time.Duration `yaml:"llm_timeout"`
	ClassificationEndpoint   string        `yaml:"classification_endpoint"`
	ClassificationTimeout    time.Duration `yaml:"classification_timeout"`
	ClassificationThreshold  float64       `yaml:"classification_threshold"`
	ClassificationBatchWindow time.Duration `yaml:"classification_batch_window"`
	ClassificationMaxBatch   int           `yaml:"classification_max_batch"`
	NATSAddr                 string        `yaml:"nats_addr"`
	InfraHosts               []string      `yaml:"infra_hosts"`
}

// Parse reads configuration from raw YAML bytes.
func Parse(data []byte) (*Config, error) {
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}
	return &cfg, nil
}

// Load reads configuration from a YAML file on disk.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file %s: %w", path, err)
	}
	cfg, err := Parse(data)
	if err != nil {
		return nil, fmt.Errorf("parsing config file %s: %w", path, err)
	}
	return cfg, nil
}

// Default returns the configuration parsed from the embedded agentcage.yaml.
// The embedded YAML is the single source of truth for all default values.
func Default(embeddedYAML []byte) (*Config, error) {
	cfg, err := Parse(embeddedYAML)
	if err != nil {
		return nil, fmt.Errorf("parsing embedded default config: %w", err)
	}
	return cfg, nil
}

// Merge applies non-zero values from override onto base, returning a new Config.
// A partial config file can override specific fields while keeping defaults for the rest.
func Merge(base, override *Config) *Config {
	result := *base

	result.CageTypes = copyMap(base.CageTypes)
	if override.CageTypes != nil {
		for k, v := range override.CageTypes {
			if existing, ok := result.CageTypes[k]; ok {
				if v.MaxDuration > 0 {
					existing.MaxDuration = v.MaxDuration
				}
				if v.MaxVCPUs > 0 {
					existing.MaxVCPUs = v.MaxVCPUs
				}
				if v.MaxMemoryMB > 0 {
					existing.MaxMemoryMB = v.MaxMemoryMB
				}
				result.CageTypes[k] = existing
			} else {
				result.CageTypes[k] = v
			}
		}
	}

	if override.RateLimits.MaxRequestsPerSecond > 0 {
		result.RateLimits = override.RateLimits
	}

	mergeTimeout := func(base, over time.Duration) time.Duration {
		if over > 0 {
			return over
		}
		return base
	}
	result.ActivityTimeouts = ActivityTimeoutsConfig{
		ValidateScope:        mergeTimeout(base.ActivityTimeouts.ValidateScope, override.ActivityTimeouts.ValidateScope),
		IssueIdentity:        mergeTimeout(base.ActivityTimeouts.IssueIdentity, override.ActivityTimeouts.IssueIdentity),
		FetchSecrets:         mergeTimeout(base.ActivityTimeouts.FetchSecrets, override.ActivityTimeouts.FetchSecrets),
		ProvisionVM:          mergeTimeout(base.ActivityTimeouts.ProvisionVM, override.ActivityTimeouts.ProvisionVM),
		ApplyPolicy:          mergeTimeout(base.ActivityTimeouts.ApplyPolicy, override.ActivityTimeouts.ApplyPolicy),
		StartAgent:           mergeTimeout(base.ActivityTimeouts.StartAgent, override.ActivityTimeouts.StartAgent),
		ExportAuditLog:       mergeTimeout(base.ActivityTimeouts.ExportAuditLog, override.ActivityTimeouts.ExportAuditLog),
		TeardownVM:           mergeTimeout(base.ActivityTimeouts.TeardownVM, override.ActivityTimeouts.TeardownVM),
		RevokeSVID:           mergeTimeout(base.ActivityTimeouts.RevokeSVID, override.ActivityTimeouts.RevokeSVID),
		RevokeVaultToken:     mergeTimeout(base.ActivityTimeouts.RevokeVaultToken, override.ActivityTimeouts.RevokeVaultToken),
		VerifyCleanup:        mergeTimeout(base.ActivityTimeouts.VerifyCleanup, override.ActivityTimeouts.VerifyCleanup),
		HeartbeatProvisionVM: mergeTimeout(base.ActivityTimeouts.HeartbeatProvisionVM, override.ActivityTimeouts.HeartbeatProvisionVM),
		HeartbeatMonitorCage: mergeTimeout(base.ActivityTimeouts.HeartbeatMonitorCage, override.ActivityTimeouts.HeartbeatMonitorCage),
	}

	result.FalcoRules = copySliceMap(base.FalcoRules)
	if override.FalcoRules != nil {
		for k, v := range override.FalcoRules {
			result.FalcoRules[k] = v
		}
	}

	result.TripwirePolicies = copyMap(base.TripwirePolicies)
	if override.TripwirePolicies != nil {
		for k, v := range override.TripwirePolicies {
			result.TripwirePolicies[k] = v
		}
	}

	result.BlocklistPatterns = copySliceMap(base.BlocklistPatterns)
	if override.BlocklistPatterns != nil {
		for k, v := range override.BlocklistPatterns {
			result.BlocklistPatterns[k] = v
		}
	}

	if override.Infrastructure.LLMEndpoint != "" {
		result.Infrastructure.LLMEndpoint = override.Infrastructure.LLMEndpoint
	}
	if override.Infrastructure.LLMTimeout > 0 {
		result.Infrastructure.LLMTimeout = override.Infrastructure.LLMTimeout
	}
	if override.Infrastructure.ClassificationEndpoint != "" {
		result.Infrastructure.ClassificationEndpoint = override.Infrastructure.ClassificationEndpoint
	}
	if override.Infrastructure.ClassificationTimeout > 0 {
		result.Infrastructure.ClassificationTimeout = override.Infrastructure.ClassificationTimeout
	}
	if override.Infrastructure.ClassificationThreshold > 0 {
		result.Infrastructure.ClassificationThreshold = override.Infrastructure.ClassificationThreshold
	}
	if override.Infrastructure.ClassificationBatchWindow > 0 {
		result.Infrastructure.ClassificationBatchWindow = override.Infrastructure.ClassificationBatchWindow
	}
	if override.Infrastructure.ClassificationMaxBatch > 0 {
		result.Infrastructure.ClassificationMaxBatch = override.Infrastructure.ClassificationMaxBatch
	}
	if override.Infrastructure.NATSAddr != "" {
		result.Infrastructure.NATSAddr = override.Infrastructure.NATSAddr
	}
	if len(override.Infrastructure.InfraHosts) > 0 {
		result.Infrastructure.InfraHosts = override.Infrastructure.InfraHosts
	}

	return &result
}

func copyMap[K comparable, V any](m map[K]V) map[K]V {
	out := make(map[K]V, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func copySliceMap[K comparable, V any](m map[K][]V) map[K][]V {
	out := make(map[K][]V, len(m))
	for k, v := range m {
		cp := make([]V, len(v))
		copy(cp, v)
		out[k] = cp
	}
	return out
}
