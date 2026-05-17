package enforcement

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/okedeji/agentcage/internal/cage"
	"github.com/okedeji/agentcage/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testLimits(t *testing.T) *config.Config {
	t.Helper()
	return config.Defaults()
}

func validDiscoveryConfig() cage.Config {
	return cage.Config{
		AssessmentID: "assess-1",
		Type:         cage.TypeDiscovery,
		BundleRef:    "abc123",
		Scope: cage.Scope{
			Host:  "example.com",
			Ports: []string{"443"},
		},
		Resources:  cage.ResourceLimits{VCPUs: 2, MemoryMB: 4096},
		TimeLimits: cage.TimeLimits{MaxDuration: 20 * time.Minute},
		RateLimits: cage.RateLimits{RequestsPerSecond: 30},
		LLM:        &cage.LLMGatewayConfig{TokenBudget: 10000, RoutingStrategy: "round_robin"},
	}
}

func validValidatorConfig() cage.Config {
	return cage.Config{
		AssessmentID:    "assess-1",
		Type:            cage.TypeValidator,
		BundleRef:       "abc123",
		Scope:           cage.Scope{Host: "target.example.com", Ports: []string{"80"}},
		Resources:       cage.ResourceLimits{VCPUs: 1, MemoryMB: 512},
		TimeLimits:      cage.TimeLimits{MaxDuration: 30 * time.Second},
		RateLimits:      cage.RateLimits{RequestsPerSecond: 5},
		ParentFindingID: "finding-123",
	}
}

func validExploitationConfig() cage.Config {
	return cage.Config{
		AssessmentID: "assess-1",
		Type:         cage.TypeExploitation,
		BundleRef:    "abc123",
		Scope:        cage.Scope{Host: "target.example.com", Ports: []string{"443"}},
		Resources:    cage.ResourceLimits{VCPUs: 2, MemoryMB: 2048},
		TimeLimits:   cage.TimeLimits{MaxDuration: 10 * time.Minute},
		RateLimits:   cage.RateLimits{RequestsPerSecond: 15},
		LLM:          &cage.LLMGatewayConfig{TokenBudget: 5000, RoutingStrategy: "round_robin"},
	}
}

func TestValidateCageConfig(t *testing.T) {
	limits := testLimits(t)

	tests := []struct {
		name      string
		modify    func(cfg *cage.Config)
		baseType  string
		wantErr   bool
		errSubstr string
	}{
		{
			name:     "valid discovery config",
			baseType: "discovery",
		},
		{
			name:     "valid validator config",
			baseType: "validator",
		},
		{
			name:     "valid exploitation config",
			baseType: "exploitation",
		},
		{
			name:      "empty scope host",
			baseType:  "discovery",
			modify:    func(cfg *cage.Config) { cfg.Scope.Host = "" },
			wantErr:   true,
			errSubstr: "must contain a host",
		},
		{
			name:      "wildcard in host",
			baseType:  "discovery",
			modify:    func(cfg *cage.Config) { cfg.Scope.Host = "*.example.com" },
			wantErr:   true,
			errSubstr: "wildcard",
		},
		{
			name:      "private IP 10.0.0.5",
			baseType:  "discovery",
			modify:    func(cfg *cage.Config) { cfg.Scope.Host = "10.0.0.5" },
			wantErr:   true,
			errSubstr: "private",
		},
		{
			name:      "private IP 172.16.0.1",
			baseType:  "discovery",
			modify:    func(cfg *cage.Config) { cfg.Scope.Host = "172.16.0.1" },
			wantErr:   true,
			errSubstr: "private",
		},
		{
			name:      "private IP 192.168.1.1",
			baseType:  "discovery",
			modify:    func(cfg *cage.Config) { cfg.Scope.Host = "192.168.1.1" },
			wantErr:   true,
			errSubstr: "private",
		},
		{
			name:      "loopback 127.0.0.1",
			baseType:  "discovery",
			modify:    func(cfg *cage.Config) { cfg.Scope.Host = "127.0.0.1" },
			wantErr:   true,
			errSubstr: "loopback",
		},
		{
			name:      "localhost",
			baseType:  "discovery",
			modify:    func(cfg *cage.Config) { cfg.Scope.Host = "localhost" },
			wantErr:   true,
			errSubstr: "loopback",
		},
		{
			name:     "domain name passes IP checks",
			baseType: "discovery",
			modify:   func(cfg *cage.Config) { cfg.Scope.Host = "example.com" },
		},
		{
			name:      "rate limit zero",
			baseType:  "discovery",
			modify:    func(cfg *cage.Config) { cfg.RateLimits.RequestsPerSecond = 0 },
			wantErr:   true,
			errSubstr: "positive",
		},
		{
			name:      "rate limit negative",
			baseType:  "discovery",
			modify:    func(cfg *cage.Config) { cfg.RateLimits.RequestsPerSecond = -1 },
			wantErr:   true,
			errSubstr: "positive",
		},
		{
			name:      "rate limit exceeds max",
			baseType:  "discovery",
			modify:    func(cfg *cage.Config) { cfg.RateLimits.RequestsPerSecond = 51 },
			wantErr:   true,
			errSubstr: "50",
		},
		{
			name:      "zero duration",
			baseType:  "discovery",
			modify:    func(cfg *cage.Config) { cfg.TimeLimits.MaxDuration = 0 },
			wantErr:   true,
			errSubstr: "positive",
		},
		{
			name:      "validator 120s exceeds 60s limit",
			baseType:  "validator",
			modify:    func(cfg *cage.Config) { cfg.TimeLimits.MaxDuration = 120 * time.Second },
			wantErr:   true,
			errSubstr: "1m0s",
		},
		{
			name:      "discovery 31min exceeds 30min limit",
			baseType:  "discovery",
			modify:    func(cfg *cage.Config) { cfg.TimeLimits.MaxDuration = 31 * time.Minute },
			wantErr:   true,
			errSubstr: "30m",
		},
		{
			name:      "validator with 2 vCPUs",
			baseType:  "validator",
			modify:    func(cfg *cage.Config) { cfg.Resources.VCPUs = 2 },
			wantErr:   true,
			errSubstr: "1 vCPU",
		},
		{
			name:      "validator with 2048 MB",
			baseType:  "validator",
			modify:    func(cfg *cage.Config) { cfg.Resources.MemoryMB = 2048 },
			wantErr:   true,
			errSubstr: "1024",
		},
		{
			name:      "discovery with 5 vCPUs",
			baseType:  "discovery",
			modify:    func(cfg *cage.Config) { cfg.Resources.VCPUs = 5 },
			wantErr:   true,
			errSubstr: "4 vCPU",
		},
		{
			name:      "validator missing ParentFindingID",
			baseType:  "validator",
			modify:    func(cfg *cage.Config) { cfg.ParentFindingID = "" },
			wantErr:   true,
			errSubstr: "ParentFindingID",
		},
		{
			name:      "discovery missing LLM",
			baseType:  "discovery",
			modify:    func(cfg *cage.Config) { cfg.LLM = nil },
			wantErr:   true,
			errSubstr: "LLM",
		},
		{
			name:      "exploitation missing LLM",
			baseType:  "exploitation",
			modify:    func(cfg *cage.Config) { cfg.LLM = nil },
			wantErr:   true,
			errSubstr: "LLM",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var cfg cage.Config
			switch tt.baseType {
			case "discovery":
				cfg = validDiscoveryConfig()
			case "validator":
				cfg = validValidatorConfig()
			case "exploitation":
				cfg = validExploitationConfig()
			}
			if tt.modify != nil {
				tt.modify(&cfg)
			}

			err := ValidateCageConfig(cfg, limits)
			if !tt.wantErr {
				assert.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.True(t, errors.Is(err, ErrInvalidConfig), "error should wrap ErrInvalidConfig")
			assert.Contains(t, err.Error(), tt.errSubstr)
		})
	}
}

func TestValidateCageConfig_MultipleViolations(t *testing.T) {
	limits := testLimits(t)
	cfg := validDiscoveryConfig()
	cfg.Scope.Host = ""
	cfg.RateLimits.RequestsPerSecond = 0
	cfg.TimeLimits.MaxDuration = 0
	cfg.Resources.VCPUs = 0
	cfg.LLM = nil

	err := ValidateCageConfig(cfg, limits)
	require.Error(t, err)

	msg := err.Error()
	assert.True(t, strings.Contains(msg, "must contain a host"), "should contain scope violation")
	assert.True(t, strings.Contains(msg, "positive"), "should contain rate limit violation")
	assert.True(t, strings.Contains(msg, "vCPU"), "should contain resource violation")
	assert.True(t, strings.Contains(msg, "LLM"), "should contain required field violation")
}
