package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the single source of truth for all agentcage platform configuration.
// One file in, everything else (Rego policies, Falco rules, SPIRE config) generated at startup.
type Config struct {
	Infrastructure InfrastructureConfig       `yaml:"infrastructure"`
	LLM            LLMConfig                  `yaml:"llm"`
	Fleet          FleetConfig                `yaml:"fleet"`
	Cages          map[string]CageTypeConfig  `yaml:"cages"`
	Assessment     AssessmentConfig           `yaml:"assessment"`
	Scope          ScopeConfig                `yaml:"scope"`
	Payload        map[string]PayloadConfig   `yaml:"payload"`
	Monitoring     map[string]MonitoringConfig `yaml:"monitoring"`
	Compliance     *ComplianceConfig          `yaml:"compliance"`
	Timeouts       ActivityTimeoutsConfig     `yaml:"timeouts"`
}

// InfrastructureConfig holds connection overrides for external services.
// All fields are optional — if omitted, agentcage runs embedded instances.
type InfrastructureConfig struct {
	Postgres *PostgresConfig  `yaml:"postgres"`
	NATS     *NATSConfig      `yaml:"nats"`
	Temporal *TemporalConfig  `yaml:"temporal"`
	SPIRE    *SPIREConfig     `yaml:"spire"`
	Vault    *VaultConfig     `yaml:"vault"`
	Falco    *FalcoConfig     `yaml:"falco"`
	Nomad    *NomadConfig     `yaml:"nomad"`
	OTel     *OTelConfig      `yaml:"otel"`
}

type PostgresConfig struct {
	URL string `yaml:"url"`
}

type NATSConfig struct {
	URL string `yaml:"url"`
}

type TemporalConfig struct {
	Address string `yaml:"address"`
}

type SPIREConfig struct {
	ServerAddress string `yaml:"server_address"`
	AgentSocket   string `yaml:"agent_socket"`
	TrustDomain   string `yaml:"trust_domain"`
}

type VaultConfig struct {
	Address  string `yaml:"address"`
	AuthPath string `yaml:"auth_path"`
	Role     string `yaml:"role"`
}

type FalcoConfig struct {
	Socket string `yaml:"socket"`
}

type NomadConfig struct {
	Address string `yaml:"address"`
}

type OTelConfig struct {
	Endpoint string `yaml:"endpoint"`
}

// LLMConfig configures the LLM provider connection.
type LLMConfig struct {
	Endpoint  string        `yaml:"endpoint"`
	APIKeyEnv string        `yaml:"api_key_env"`
	Timeout   time.Duration `yaml:"timeout"`
	Models    []ModelConfig `yaml:"models"`
}

type ModelConfig struct {
	Name     string `yaml:"name"`
	Priority int    `yaml:"priority"`
}

// FleetConfig defines bare metal hosts for multi-host mode.
type FleetConfig struct {
	Hosts      []HostConfig      `yaml:"hosts"`
	Autoscaler *AutoscalerConfig `yaml:"autoscaler"`
}

type HostConfig struct {
	Address  string `yaml:"address"`
	VCPUs    int32  `yaml:"vcpus"`
	MemoryMB int32  `yaml:"memory_mb"`
	CageSlots int32 `yaml:"cage_slots"`
}

type AutoscalerConfig struct {
	MinWarmHosts int32 `yaml:"min_warm_hosts"`
	MaxHosts     int32 `yaml:"max_hosts"`
}

// CageTypeConfig defines resource and behavioral limits for a cage type.
type CageTypeConfig struct {
	MaxDuration          time.Duration `yaml:"max_duration"`
	MaxVCPUs             int32         `yaml:"max_vcpus"`
	MaxMemoryMB          int32         `yaml:"max_memory_mb"`
	MaxConcurrent        int32         `yaml:"max_concurrent"`
	RequiresLLM          bool          `yaml:"requires_llm"`
	RequiresParentFinding bool         `yaml:"requires_parent_finding"`
	RateLimit            int32         `yaml:"rate_limit"`
	MaxChainDepth        int32         `yaml:"max_chain_depth"`
}

// AssessmentConfig defines defaults for assessment execution.
type AssessmentConfig struct {
	MaxDuration   time.Duration `yaml:"max_duration"`
	TokenBudget   int64         `yaml:"token_budget"`
	MaxIterations int32         `yaml:"max_iterations"`
	ReviewTimeout time.Duration `yaml:"review_timeout"`
}

// ScopeConfig defines what targets are allowed or denied.
type ScopeConfig struct {
	Deny          []string `yaml:"deny"`
	DenyWildcards bool     `yaml:"deny_wildcards"`
	DenyLocalhost bool     `yaml:"deny_localhost"`
}

// PayloadConfig defines blocklist patterns for a vulnerability class.
type PayloadConfig struct {
	Block []PatternEntry `yaml:"block"`
}

// PatternEntry is a single regex pattern with a human-readable reason.
type PatternEntry struct {
	Pattern string `yaml:"pattern"`
	Reason  string `yaml:"reason"`
}

// MonitoringConfig defines behavioral monitoring rules for a cage type.
type MonitoringConfig struct {
	Rules            map[string]MonitoringRule `yaml:"rules"`
	AllowedProcesses []string                  `yaml:"allowed_processes"`
	DefaultAction    string                    `yaml:"default_action"`
}

// MonitoringRule is a human-readable behavioral detection rule.
// agentcage generates Falco rules from these at startup.
type MonitoringRule struct {
	Detect string `yaml:"detect"`
	Action string `yaml:"action"`
}

// ComplianceConfig enables optional compliance framework enforcement.
type ComplianceConfig struct {
	Framework          string        `yaml:"framework"`
	AuditRetention     string        `yaml:"audit_retention"`
	MaxConcurrentCages int32         `yaml:"max_concurrent_cages"`
	RequireIntervention bool         `yaml:"require_intervention"`
	InterventionTimeout time.Duration `yaml:"intervention_timeout"`
}

// ActivityTimeoutsConfig holds Temporal activity timeouts.
// Rarely needs changing — sensible defaults are applied.
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

// Defaults returns configuration with secure defaults for all values.
// Used when no config file is provided — everything runs embedded.
func Defaults() *Config {
	return &Config{
		LLM: LLMConfig{
			Timeout: 30 * time.Second,
		},
		Cages: map[string]CageTypeConfig{
			"discovery": {
				MaxDuration:   30 * time.Minute,
				MaxVCPUs:      4,
				MaxMemoryMB:   8192,
				MaxConcurrent: 10,
				RequiresLLM:   true,
				RateLimit:     1000,
			},
			"validator": {
				MaxDuration:           60 * time.Second,
				MaxVCPUs:              1,
				MaxMemoryMB:           1024,
				MaxConcurrent:         20,
				RequiresLLM:           false,
				RequiresParentFinding: true,
				RateLimit:             100,
			},
			"escalation": {
				MaxDuration:           15 * time.Minute,
				MaxVCPUs:              2,
				MaxMemoryMB:           4096,
				MaxConcurrent:         5,
				RequiresLLM:           true,
				RequiresParentFinding: true,
				RateLimit:             500,
				MaxChainDepth:         3,
			},
		},
		Assessment: AssessmentConfig{
			MaxDuration:   4 * time.Hour,
			TokenBudget:   500000,
			MaxIterations: 20,
			ReviewTimeout: 24 * time.Hour,
		},
		Scope: ScopeConfig{
			Deny: []string{
				"10.0.0.0/8",
				"172.16.0.0/12",
				"192.168.0.0/16",
				"127.0.0.0/8",
				"::1",
				"169.254.169.254",
				"orchestrator.agentcage.internal",
				"vault.agentcage.internal",
				"spire.agentcage.internal",
				"nats.agentcage.internal",
				"temporal.agentcage.internal",
				"postgres.agentcage.internal",
			},
			DenyWildcards: true,
			DenyLocalhost: true,
		},
		Payload: defaultPayload(),
		Monitoring: map[string]MonitoringConfig{
			"discovery": {
				Rules: map[string]MonitoringRule{
					"privileged_shell":      {Detect: "root shell spawn", Action: "human_review"},
					"sensitive_file_write":  {Detect: "write to /etc, /proc, /sys", Action: "log"},
					"privilege_escalation":  {Detect: "setuid, setgid, sudo", Action: "kill"},
					"fork_bomb":            {Detect: "rapid process forking", Action: "log"},
				},
				DefaultAction: "log",
			},
			"validator": {
				Rules: map[string]MonitoringRule{
					"any_shell":            {Detect: "any shell spawn", Action: "kill"},
					"any_file_write":       {Detect: "any filesystem write", Action: "human_review"},
					"unexpected_network":   {Detect: "connection outside target scope", Action: "log"},
					"privilege_escalation": {Detect: "setuid, setgid, sudo", Action: "kill"},
					"unexpected_process":   {Detect: "process not in allowlist", Action: "kill"},
				},
				AllowedProcesses: []string{"agent", "payload-proxy", "findings-sidecar"},
				DefaultAction:    "human_review",
			},
			"escalation": {
				Rules: map[string]MonitoringRule{
					"privileged_shell":     {Detect: "root shell spawn", Action: "human_review"},
					"sensitive_file_write": {Detect: "write to /etc, /proc, /sys", Action: "human_review"},
					"privilege_escalation": {Detect: "setuid, setgid, sudo", Action: "kill"},
					"lateral_movement":    {Detect: "SSH, RDP, SMB connections", Action: "kill"},
				},
				DefaultAction: "human_review",
			},
		},
		Timeouts: defaultTimeouts(),
	}
}

func defaultTimeouts() ActivityTimeoutsConfig {
	return ActivityTimeoutsConfig{
		ValidateScope:        5 * time.Second,
		IssueIdentity:        10 * time.Second,
		FetchSecrets:         5 * time.Second,
		ProvisionVM:          30 * time.Second,
		ApplyPolicy:          10 * time.Second,
		StartAgent:           5 * time.Second,
		ExportAuditLog:       15 * time.Second,
		TeardownVM:           15 * time.Second,
		RevokeSVID:           5 * time.Second,
		RevokeVaultToken:     5 * time.Second,
		VerifyCleanup:        10 * time.Second,
		HeartbeatProvisionVM: 10 * time.Second,
		HeartbeatMonitorCage: 30 * time.Second,
	}
}

func defaultPayload() map[string]PayloadConfig {
	return map[string]PayloadConfig{
		"sqli": {Block: []PatternEntry{
			{Pattern: `(?i)\bDROP\s+(TABLE|DATABASE|INDEX|VIEW)`, Reason: "destructive SQL: DROP"},
			{Pattern: `(?i)\bDELETE\s+FROM\b`, Reason: "destructive SQL: DELETE"},
			{Pattern: `(?i)\bTRUNCATE\s+`, Reason: "destructive SQL: TRUNCATE"},
			{Pattern: `(?i)\bUPDATE\s+\w+\s+SET\b`, Reason: "destructive SQL: UPDATE"},
			{Pattern: `(?i)\bALTER\s+(TABLE|DATABASE|USER)`, Reason: "destructive SQL: ALTER"},
			{Pattern: `(?i)\bGRANT\s+`, Reason: "privilege escalation: GRANT"},
			{Pattern: `(?i)\bCREATE\s+(USER|ROLE)`, Reason: "privilege escalation: CREATE USER/ROLE"},
		}},
		"rce": {Block: []PatternEntry{
			{Pattern: `(?i)\brm\s+-rf\b`, Reason: "destructive: rm -rf"},
			{Pattern: `(?i)\bmkfs\b`, Reason: "destructive: mkfs"},
			{Pattern: `(?i)\bdd\s+`, Reason: "destructive: dd"},
			{Pattern: `(?i)\bshutdown\b`, Reason: "destructive: shutdown"},
			{Pattern: `(?i)\breboot\b`, Reason: "destructive: reboot"},
			{Pattern: `(?i):\(\)\s*\{\s*:\|\s*:&\s*\}\s*;`, Reason: "fork bomb"},
			{Pattern: `(?i)>\s*/etc/(passwd|shadow|sudoers)`, Reason: "write to sensitive system file"},
			{Pattern: `(?i)\bcurl\s+.*\|\s*(bash|sh)`, Reason: "remote code download and execute"},
		}},
		"ssrf": {Block: []PatternEntry{
			{Pattern: `(?i)(^|=)https?://(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)`, Reason: "SSRF to private IP"},
			{Pattern: `(?i)(^|=)https?://127\.`, Reason: "SSRF to loopback"},
			{Pattern: `(?i)(^|=)https?://localhost`, Reason: "SSRF to localhost"},
			{Pattern: `(?i)(^|=)https?://169\.254\.169\.254`, Reason: "SSRF to cloud metadata"},
		}},
		"xss": {Block: []PatternEntry{
			{Pattern: `(?i)\bDROP\s+(TABLE|DATABASE)`, Reason: "destructive SQL in XSS context"},
		}},
	}
}

// Merge applies non-zero values from override onto base, returning a new Config.
func Merge(base, override *Config) *Config {
	result := *base

	// Infrastructure: override individual service configs if provided
	if override.Infrastructure.Postgres != nil {
		result.Infrastructure.Postgres = override.Infrastructure.Postgres
	}
	if override.Infrastructure.NATS != nil {
		result.Infrastructure.NATS = override.Infrastructure.NATS
	}
	if override.Infrastructure.Temporal != nil {
		result.Infrastructure.Temporal = override.Infrastructure.Temporal
	}
	if override.Infrastructure.SPIRE != nil {
		result.Infrastructure.SPIRE = override.Infrastructure.SPIRE
	}
	if override.Infrastructure.Vault != nil {
		result.Infrastructure.Vault = override.Infrastructure.Vault
	}
	if override.Infrastructure.Falco != nil {
		result.Infrastructure.Falco = override.Infrastructure.Falco
	}
	if override.Infrastructure.Nomad != nil {
		result.Infrastructure.Nomad = override.Infrastructure.Nomad
	}
	if override.Infrastructure.OTel != nil {
		result.Infrastructure.OTel = override.Infrastructure.OTel
	}

	// LLM
	if override.LLM.Endpoint != "" {
		result.LLM.Endpoint = override.LLM.Endpoint
	}
	if override.LLM.APIKeyEnv != "" {
		result.LLM.APIKeyEnv = override.LLM.APIKeyEnv
	}
	if override.LLM.Timeout > 0 {
		result.LLM.Timeout = override.LLM.Timeout
	}
	if len(override.LLM.Models) > 0 {
		models := make([]ModelConfig, len(override.LLM.Models))
		copy(models, override.LLM.Models)
		result.LLM.Models = models
	}

	// Fleet
	if len(override.Fleet.Hosts) > 0 {
		result.Fleet.Hosts = override.Fleet.Hosts
	}
	if override.Fleet.Autoscaler != nil {
		result.Fleet.Autoscaler = override.Fleet.Autoscaler
	}

	// Cages
	result.Cages = copyCageTypes(base.Cages)
	if override.Cages != nil {
		for k, v := range override.Cages {
			if existing, ok := result.Cages[k]; ok {
				if v.MaxDuration > 0 {
					existing.MaxDuration = v.MaxDuration
				}
				if v.MaxVCPUs > 0 {
					existing.MaxVCPUs = v.MaxVCPUs
				}
				if v.MaxMemoryMB > 0 {
					existing.MaxMemoryMB = v.MaxMemoryMB
				}
				if v.MaxConcurrent > 0 {
					existing.MaxConcurrent = v.MaxConcurrent
				}
				if v.RateLimit > 0 {
					existing.RateLimit = v.RateLimit
				}
				if v.MaxChainDepth > 0 {
					existing.MaxChainDepth = v.MaxChainDepth
				}
				if v.RequiresLLM {
					existing.RequiresLLM = true
				}
				if v.RequiresParentFinding {
					existing.RequiresParentFinding = true
				}
				result.Cages[k] = existing
			} else {
				result.Cages[k] = v
			}
		}
	}

	// Assessment
	if override.Assessment.MaxDuration > 0 {
		result.Assessment.MaxDuration = override.Assessment.MaxDuration
	}
	if override.Assessment.TokenBudget > 0 {
		result.Assessment.TokenBudget = override.Assessment.TokenBudget
	}
	if override.Assessment.MaxIterations > 0 {
		result.Assessment.MaxIterations = override.Assessment.MaxIterations
	}
	if override.Assessment.ReviewTimeout > 0 {
		result.Assessment.ReviewTimeout = override.Assessment.ReviewTimeout
	}

	// Scope
	if len(override.Scope.Deny) > 0 {
		result.Scope.Deny = override.Scope.Deny
	}
	if override.Scope.DenyWildcards {
		result.Scope.DenyWildcards = true
	}
	if override.Scope.DenyLocalhost {
		result.Scope.DenyLocalhost = true
	}

	// Payload
	if override.Payload != nil {
		result.Payload = copyPayload(base.Payload)
		for k, v := range override.Payload {
			result.Payload[k] = v
		}
	} else {
		result.Payload = copyPayload(base.Payload)
	}

	// Monitoring
	if override.Monitoring != nil {
		result.Monitoring = copyMonitoring(base.Monitoring)
		for k, v := range override.Monitoring {
			result.Monitoring[k] = v
		}
	} else {
		result.Monitoring = copyMonitoring(base.Monitoring)
	}

	// Compliance
	if override.Compliance != nil {
		result.Compliance = override.Compliance
	}

	// Timeouts
	result.Timeouts = mergeTimeouts(base.Timeouts, override.Timeouts)

	return &result
}

func mergeTimeouts(base, override ActivityTimeoutsConfig) ActivityTimeoutsConfig {
	mt := func(b, o time.Duration) time.Duration {
		if o > 0 {
			return o
		}
		return b
	}
	return ActivityTimeoutsConfig{
		ValidateScope:        mt(base.ValidateScope, override.ValidateScope),
		IssueIdentity:        mt(base.IssueIdentity, override.IssueIdentity),
		FetchSecrets:         mt(base.FetchSecrets, override.FetchSecrets),
		ProvisionVM:          mt(base.ProvisionVM, override.ProvisionVM),
		ApplyPolicy:          mt(base.ApplyPolicy, override.ApplyPolicy),
		StartAgent:           mt(base.StartAgent, override.StartAgent),
		ExportAuditLog:       mt(base.ExportAuditLog, override.ExportAuditLog),
		TeardownVM:           mt(base.TeardownVM, override.TeardownVM),
		RevokeSVID:           mt(base.RevokeSVID, override.RevokeSVID),
		RevokeVaultToken:     mt(base.RevokeVaultToken, override.RevokeVaultToken),
		VerifyCleanup:        mt(base.VerifyCleanup, override.VerifyCleanup),
		HeartbeatProvisionVM: mt(base.HeartbeatProvisionVM, override.HeartbeatProvisionVM),
		HeartbeatMonitorCage: mt(base.HeartbeatMonitorCage, override.HeartbeatMonitorCage),
	}
}

func copyCageTypes(m map[string]CageTypeConfig) map[string]CageTypeConfig {
	out := make(map[string]CageTypeConfig, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func copyPayload(m map[string]PayloadConfig) map[string]PayloadConfig {
	out := make(map[string]PayloadConfig, len(m))
	for k, v := range m {
		entries := make([]PatternEntry, len(v.Block))
		copy(entries, v.Block)
		out[k] = PayloadConfig{Block: entries}
	}
	return out
}

func copyMonitoring(m map[string]MonitoringConfig) map[string]MonitoringConfig {
	out := make(map[string]MonitoringConfig, len(m))
	for k, v := range m {
		rules := make(map[string]MonitoringRule, len(v.Rules))
		for rk, rv := range v.Rules {
			rules[rk] = rv
		}
		procs := make([]string, len(v.AllowedProcesses))
		copy(procs, v.AllowedProcesses)
		out[k] = MonitoringConfig{
			Rules:            rules,
			AllowedProcesses: procs,
			DefaultAction:    v.DefaultAction,
		}
	}
	return out
}

// IsExternal returns true if the user provided their own service address.
func (c *InfrastructureConfig) IsExternalPostgres() bool {
	return c.Postgres != nil && c.Postgres.URL != ""
}

func (c *InfrastructureConfig) IsExternalNATS() bool {
	return c.NATS != nil && c.NATS.URL != ""
}

func (c *InfrastructureConfig) IsExternalTemporal() bool {
	return c.Temporal != nil && c.Temporal.Address != ""
}

func (c *InfrastructureConfig) IsExternalSPIRE() bool {
	return c.SPIRE != nil && c.SPIRE.ServerAddress != ""
}

func (c *InfrastructureConfig) IsExternalVault() bool {
	return c.Vault != nil && c.Vault.Address != ""
}

func (c *InfrastructureConfig) IsExternalFalco() bool {
	return c.Falco != nil && c.Falco.Socket != ""
}

func (c *InfrastructureConfig) IsExternalNomad() bool {
	return c.Nomad != nil && c.Nomad.Address != ""
}

func (c *InfrastructureConfig) IsExternalOTel() bool {
	return c.OTel != nil && c.OTel.Endpoint != ""
}

// InfraDenyList returns the list of infrastructure addresses that cages must never target.
// Combines user-provided scope.deny with auto-detected embedded service addresses.
func (c *Config) InfraDenyList() []string {
	deny := make([]string, len(c.Scope.Deny))
	copy(deny, c.Scope.Deny)
	return deny
}

// BlocklistPatterns returns payload patterns in the format the proxy engine expects.
// Maps from the new config format (payload.sqli.block) to pattern+message pairs.
func (c *Config) BlocklistPatterns() map[string][]PatternEntry {
	out := make(map[string][]PatternEntry, len(c.Payload))
	for class, pc := range c.Payload {
		out[class] = pc.Block
	}
	return out
}

// RateLimit returns the rate limit for a given cage type, or 0 if not set.
func (c *Config) RateLimit(cageType string) int32 {
	if ct, ok := c.Cages[cageType]; ok {
		return ct.RateLimit
	}
	return 0
}

// ValidCageTypes are the recognized cage type string keys.
var ValidCageTypes = map[string]bool{
	"discovery":  true,
	"validator":  true,
	"escalation": true,
}

// IsValidCageType returns true if the given string is a recognized cage type.
func IsValidCageType(s string) bool {
	return ValidCageTypes[s]
}
