package enforcement

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/okedeji/agentcage/internal/cage"
	"github.com/okedeji/agentcage/internal/config"
)

func newEngine(t *testing.T) *OPAEngine {
	t.Helper()
	cfg := config.Defaults()
	modules := GenerateRegoModules(cfg)
	e, err := NewOPAEngineFromModules(modules)
	require.NoError(t, err)
	return e
}

func newEngineWithCompliance(t *testing.T, framework string) *OPAEngine {
	t.Helper()
	cfg := config.Defaults()
	cfg.Compliance = &config.ComplianceConfig{Framework: framework}
	switch framework {
	case "soc2":
		cfg.Compliance.MaxConcurrentCages = 500
		cfg.Compliance.RequireIntervention = true
		cfg.Compliance.InterventionTimeout = 30 * time.Minute
	case "hipaa":
		cfg.Compliance.MaxConcurrentCages = 200
		cfg.Compliance.RequireIntervention = true
	}
	modules := GenerateRegoModules(cfg)
	e, err := NewOPAEngineFromModules(modules)
	require.NoError(t, err)
	return e
}

func testDenyList(t *testing.T) []string {
	t.Helper()
	cfg := config.Defaults()
	return cfg.Scope.Deny
}

func TestOPAScope(t *testing.T) {
	e := newEngine(t)
	ctx := context.Background()
	denyList := testDenyList(t)

	tests := []struct {
		name        string
		scope       cage.Scope
		wantAllowed bool
		wantSubstr  string
	}{
		{
			name:        "valid external host",
			scope:       cage.Scope{Hosts: []string{"example.com"}},
			wantAllowed: true,
		},
		{
			name:        "empty hosts",
			scope:       cage.Scope{Hosts: []string{}},
			wantAllowed: false,
			wantSubstr:  "at least one host",
		},
		{
			name:        "wildcard host",
			scope:       cage.Scope{Hosts: []string{"*"}},
			wantAllowed: false,
			wantSubstr:  "wildcard",
		},
		{
			name:        "wildcard in host",
			scope:       cage.Scope{Hosts: []string{"*.example.com"}},
			wantAllowed: false,
			wantSubstr:  "wildcard",
		},
		{
			name:        "private 10.x range",
			scope:       cage.Scope{Hosts: []string{"10.0.0.5"}},
			wantAllowed: false,
			wantSubstr:  "private IP range",
		},
		{
			name:        "private 172.16.x range",
			scope:       cage.Scope{Hosts: []string{"172.16.0.1"}},
			wantAllowed: false,
			wantSubstr:  "private IP range",
		},
		{
			name:        "private 192.168.x range",
			scope:       cage.Scope{Hosts: []string{"192.168.1.1"}},
			wantAllowed: false,
			wantSubstr:  "private IP range",
		},
		{
			name:        "localhost",
			scope:       cage.Scope{Hosts: []string{"localhost"}},
			wantAllowed: false,
			wantSubstr:  "localhost",
		},
		{
			name:        "loopback 127.0.0.1",
			scope:       cage.Scope{Hosts: []string{"127.0.0.1"}},
			wantAllowed: false,
			wantSubstr:  "loopback",
		},
		{
			name:        "IPv6 loopback",
			scope:       cage.Scope{Hosts: []string{"::1"}},
			wantAllowed: false,
			wantSubstr:  "IPv6 loopback",
		},
		{
			name:        "denied host vault",
			scope:       cage.Scope{Hosts: []string{"vault.agentcage.internal"}},
			wantAllowed: false,
			wantSubstr:  "not allowed in scope",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decision, err := e.EvaluateScope(ctx, tt.scope, denyList)
			require.NoError(t, err)
			assert.Equal(t, tt.wantAllowed, decision.Allowed)
			if tt.wantSubstr != "" {
				assert.Contains(t, decision.Reason, tt.wantSubstr)
			}
		})
	}
}

func TestOPACageConfig(t *testing.T) {
	e := newEngine(t)
	ctx := context.Background()

	validDiscovery := cage.Config{
		Type:            cage.TypeDiscovery,
		TimeLimits:      cage.TimeLimits{MaxDuration: 10 * time.Minute},
		Resources:       cage.ResourceLimits{VCPUs: 2, MemoryMB: 4096},
		LLM:             &cage.LLMGatewayConfig{TokenBudget: 10000, RoutingStrategy: "round_robin"},
		RateLimits:      cage.RateLimits{RequestsPerSecond: 100},
		ParentFindingID: "",
	}

	validValidator := cage.Config{
		Type:            cage.TypeValidator,
		TimeLimits:      cage.TimeLimits{MaxDuration: 30 * time.Second},
		Resources:       cage.ResourceLimits{VCPUs: 1, MemoryMB: 512},
		LLM:             nil,
		RateLimits:      cage.RateLimits{RequestsPerSecond: 50},
		ParentFindingID: "finding-123",
	}

	tests := []struct {
		name        string
		config      cage.Config
		wantAllowed bool
		wantSubstr  string
	}{
		{
			name:        "valid discovery config",
			config:      validDiscovery,
			wantAllowed: true,
		},
		{
			name:        "valid validator config",
			config:      validValidator,
			wantAllowed: true,
		},
		{
			name: "validator with LLM config",
			config: func() cage.Config {
				c := validValidator
				c.LLM = &cage.LLMGatewayConfig{TokenBudget: 100}
				return c
			}(),
			wantAllowed: false,
			wantSubstr:  "must not have LLM access",
		},
		{
			name: "validator with 120s time limit",
			config: func() cage.Config {
				c := validValidator
				c.TimeLimits.MaxDuration = 120 * time.Second
				return c
			}(),
			wantAllowed: false,
			wantSubstr:  "cannot exceed 60 seconds",
		},
		{
			name: "validator with 2 vCPUs",
			config: func() cage.Config {
				c := validValidator
				c.Resources.VCPUs = 2
				return c
			}(),
			wantAllowed: false,
			wantSubstr:  "cannot exceed 1 vCPU",
		},
		{
			name: "validator with 2048 MB RAM",
			config: func() cage.Config {
				c := validValidator
				c.Resources.MemoryMB = 2048
				return c
			}(),
			wantAllowed: false,
			wantSubstr:  "cannot exceed 1024 MB RAM",
		},
		{
			name: "validator without parent finding",
			config: func() cage.Config {
				c := validValidator
				c.ParentFindingID = ""
				return c
			}(),
			wantAllowed: false,
			wantSubstr:  "parent finding ID",
		},
		{
			name: "discovery without LLM",
			config: func() cage.Config {
				c := validDiscovery
				c.LLM = nil
				return c
			}(),
			wantAllowed: false,
			wantSubstr:  "LLM gateway configuration",
		},
		{
			name: "discovery with 3600s time limit",
			config: func() cage.Config {
				c := validDiscovery
				c.TimeLimits.MaxDuration = 3600 * time.Second
				return c
			}(),
			wantAllowed: false,
			wantSubstr:  "cannot exceed 1800 seconds",
		},
		{
			name: "escalation without parent finding",
			config: cage.Config{
				Type:            cage.TypeEscalation,
				TimeLimits:      cage.TimeLimits{MaxDuration: 5 * time.Minute},
				Resources:       cage.ResourceLimits{VCPUs: 1, MemoryMB: 2048},
				LLM:             &cage.LLMGatewayConfig{TokenBudget: 5000},
				RateLimits:      cage.RateLimits{RequestsPerSecond: 50},
				ParentFindingID: "",
			},
			wantAllowed: false,
			wantSubstr:  "parent finding ID",
		},
		{
			name: "rate limit zero",
			config: func() cage.Config {
				c := validDiscovery
				c.RateLimits.RequestsPerSecond = 0
				return c
			}(),
			wantAllowed: false,
			wantSubstr:  "rate limit must be positive",
		},
		{
			name: "rate limit 1500",
			config: func() cage.Config {
				c := validDiscovery
				c.RateLimits.RequestsPerSecond = 1500
				return c
			}(),
			wantAllowed: false,
			wantSubstr:  "cannot exceed 1000",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decision, err := e.EvaluateCageConfig(ctx, tt.config)
			require.NoError(t, err)
			assert.Equal(t, tt.wantAllowed, decision.Allowed)
			if tt.wantSubstr != "" {
				assert.Contains(t, decision.Reason, tt.wantSubstr)
			}
		})
	}
}

func TestOPAPayload(t *testing.T) {
	e := newEngine(t)
	ctx := context.Background()

	tests := []struct {
		name       string
		vulnClass  string
		payload    string
		wantResult PayloadDecision
	}{
		{
			name:       "sqli select allowed",
			vulnClass:  "sqli",
			payload:    "SELECT * FROM users",
			wantResult: PayloadAllow,
		},
		{
			name:       "sqli drop blocked",
			vulnClass:  "sqli",
			payload:    "DROP TABLE users",
			wantResult: PayloadBlock,
		},
		{
			name:       "sqli delete blocked",
			vulnClass:  "sqli",
			payload:    "DELETE FROM users WHERE id=1",
			wantResult: PayloadBlock,
		},
		{
			name:       "rce whoami allowed",
			vulnClass:  "rce",
			payload:    "whoami",
			wantResult: PayloadAllow,
		},
		{
			name:       "rce rm -rf blocked",
			vulnClass:  "rce",
			payload:    "rm -rf /",
			wantResult: PayloadBlock,
		},
		{
			name:       "rce fork bomb blocked",
			vulnClass:  "rce",
			payload:    ":() { :|:& } ;",
			wantResult: PayloadBlock,
		},
		{
			name:       "xss script tag allowed",
			vulnClass:  "xss",
			payload:    "<script>alert(1)</script>",
			wantResult: PayloadAllow,
		},
		{
			name:       "ssrf private IP blocked",
			vulnClass:  "ssrf",
			payload:    "http://10.0.0.5/admin",
			wantResult: PayloadBlock,
		},
		{
			name:       "ssrf cloud metadata blocked",
			vulnClass:  "ssrf",
			payload:    "http://169.254.169.254/metadata",
			wantResult: PayloadBlock,
		},
		{
			name:       "unknown vuln class allowed",
			vulnClass:  "unknown",
			payload:    "anything",
			wantResult: PayloadAllow,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, reason, err := e.EvaluatePayload(ctx, tt.vulnClass, tt.payload)
			require.NoError(t, err)
			assert.Equal(t, tt.wantResult, result)
			if tt.wantResult == PayloadBlock {
				assert.NotEmpty(t, reason)
			}
		})
	}
}

func TestOPACompliance(t *testing.T) {
	ctx := context.Background()

	t.Run("soc2 compliant", func(t *testing.T) {
		e := newEngineWithCompliance(t, "soc2")
		decision, err := e.EvaluateCompliance(ctx, "soc2", map[string]any{
			"max_concurrent_cages":         100,
			"audit_log_enabled":            true,
			"intervention_enabled":         true,
			"intervention_timeout_minutes": 15,
		})
		require.NoError(t, err)
		assert.True(t, decision.Allowed)
	})

	t.Run("soc2 audit disabled", func(t *testing.T) {
		e := newEngineWithCompliance(t, "soc2")
		decision, err := e.EvaluateCompliance(ctx, "soc2", map[string]any{
			"max_concurrent_cages":         100,
			"audit_log_enabled":            false,
			"intervention_enabled":         true,
			"intervention_timeout_minutes": 15,
		})
		require.NoError(t, err)
		assert.False(t, decision.Allowed)
		assert.Contains(t, decision.Reason, "audit logging")
	})

	t.Run("soc2 too many concurrent cages", func(t *testing.T) {
		e := newEngineWithCompliance(t, "soc2")
		decision, err := e.EvaluateCompliance(ctx, "soc2", map[string]any{
			"max_concurrent_cages":         600,
			"audit_log_enabled":            true,
			"intervention_enabled":         true,
			"intervention_timeout_minutes": 15,
		})
		require.NoError(t, err)
		assert.False(t, decision.Allowed)
		assert.Contains(t, decision.Reason, "500")
	})

	t.Run("soc2 intervention not enabled", func(t *testing.T) {
		e := newEngineWithCompliance(t, "soc2")
		decision, err := e.EvaluateCompliance(ctx, "soc2", map[string]any{
			"max_concurrent_cages":         100,
			"audit_log_enabled":            true,
			"intervention_enabled":         false,
			"intervention_timeout_minutes": 15,
		})
		require.NoError(t, err)
		assert.False(t, decision.Allowed)
		assert.Contains(t, decision.Reason, "intervention")
	})

	t.Run("hipaa compliant", func(t *testing.T) {
		e := newEngineWithCompliance(t, "hipaa")
		decision, err := e.EvaluateCompliance(ctx, "hipaa", map[string]any{
			"max_concurrent_cages": 50,
			"audit_log_enabled":    true,
			"intervention_enabled": true,
		})
		require.NoError(t, err)
		assert.True(t, decision.Allowed)
	})

	t.Run("hipaa too many cages", func(t *testing.T) {
		e := newEngineWithCompliance(t, "hipaa")
		decision, err := e.EvaluateCompliance(ctx, "hipaa", map[string]any{
			"max_concurrent_cages": 300,
			"audit_log_enabled":    true,
			"intervention_enabled": true,
		})
		require.NoError(t, err)
		assert.False(t, decision.Allowed)
		assert.Contains(t, decision.Reason, "200")
	})

	t.Run("unknown framework", func(t *testing.T) {
		e := newEngine(t)
		_, err := e.EvaluateCompliance(ctx, "pci_dss", map[string]any{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no compliance policy")
	})
}
