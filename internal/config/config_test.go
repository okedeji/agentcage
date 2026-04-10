package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaults_ReturnsPopulatedConfig(t *testing.T) {
	cfg := Defaults()
	require.NotNil(t, cfg)
	assert.NotEmpty(t, cfg.Cages)
	assert.NotEmpty(t, cfg.Monitoring)
	assert.NotEmpty(t, cfg.Payload)
	assert.NotEmpty(t, cfg.Scope.Deny)
}

func TestDefaults_HasThreeCageTypes(t *testing.T) {
	cfg := Defaults()
	require.Len(t, cfg.Cages, 3)

	disc := cfg.Cages["discovery"]
	assert.Equal(t, 30*time.Minute, disc.MaxDuration)
	assert.Equal(t, int32(4), disc.MaxVCPUs)
	assert.Equal(t, int32(8192), disc.MaxMemoryMB)
	assert.True(t, disc.RequiresLLM)

	val := cfg.Cages["validator"]
	assert.Equal(t, 60*time.Second, val.MaxDuration)
	assert.Equal(t, int32(1), val.MaxVCPUs)
	assert.Equal(t, int32(1024), val.MaxMemoryMB)
	assert.True(t, val.RequiresParentFinding)

	esc := cfg.Cages["escalation"]
	assert.Equal(t, 15*time.Minute, esc.MaxDuration)
	assert.Equal(t, int32(2), esc.MaxVCPUs)
	assert.Equal(t, int32(4096), esc.MaxMemoryMB)
	assert.Equal(t, int32(3), esc.MaxChainDepth)
}

func TestDefaults_HasAllActivityTimeouts(t *testing.T) {
	cfg := Defaults()
	at := cfg.Timeouts

	assert.Equal(t, 5*time.Second, at.ValidateScope)
	assert.Equal(t, 10*time.Second, at.IssueIdentity)
	assert.Equal(t, 5*time.Second, at.FetchSecrets)
	assert.Equal(t, 30*time.Second, at.ProvisionVM)
	assert.Equal(t, 10*time.Second, at.ApplyPolicy)
	assert.Equal(t, 5*time.Second, at.StartAgent)
	assert.Equal(t, 15*time.Second, at.ExportAuditLog)
	assert.Equal(t, 15*time.Second, at.TeardownVM)
	assert.Equal(t, 5*time.Second, at.RevokeSVID)
	assert.Equal(t, 5*time.Second, at.RevokeVaultToken)
	assert.Equal(t, 10*time.Second, at.VerifyCleanup)
	assert.Equal(t, 10*time.Second, at.HeartbeatProvisionVM)
	assert.Equal(t, 30*time.Second, at.HeartbeatMonitorCage)
}

func TestDefaults_HasThreeMonitoringSets(t *testing.T) {
	cfg := Defaults()
	require.Len(t, cfg.Monitoring, 3)
	assert.Contains(t, cfg.Monitoring, "discovery")
	assert.Contains(t, cfg.Monitoring, "validator")
	assert.Contains(t, cfg.Monitoring, "escalation")
}

func TestDefaults_HasPayloadSets(t *testing.T) {
	cfg := Defaults()
	require.Len(t, cfg.Payload, 7)
	assert.Contains(t, cfg.Payload, "sqli")
	assert.Contains(t, cfg.Payload, "rce")
	assert.Contains(t, cfg.Payload, "ssrf")
	assert.Contains(t, cfg.Payload, "xss")
	assert.Contains(t, cfg.Payload, "path_traversal")
	assert.Contains(t, cfg.Payload, "xxe")
	assert.Contains(t, cfg.Payload, "ldap_injection")
}

func TestDefaults_ScopeDenyIncludesPrivateRanges(t *testing.T) {
	cfg := Defaults()
	assert.Contains(t, cfg.Scope.Deny, "10.0.0.0/8")
	assert.Contains(t, cfg.Scope.Deny, "172.16.0.0/12")
	assert.Contains(t, cfg.Scope.Deny, "192.168.0.0/16")
	assert.Contains(t, cfg.Scope.Deny, "127.0.0.0/8")
	assert.Contains(t, cfg.Scope.Deny, "169.254.0.0/16")
	assert.Contains(t, cfg.Scope.Deny, "fc00::/7")
	assert.Contains(t, cfg.Scope.Deny, "fe80::/10")
	// Defaults() leaves the deny pointers nil; the posture default supplies
	// the value. PostureStrict (the zero value) → deny by default.
	assert.True(t, cfg.ScopeDenyWildcardsDefault())
	assert.True(t, cfg.ScopeDenyLocalhostDefault())
}

func TestDefaults_AssessmentDefaults(t *testing.T) {
	cfg := Defaults()
	assert.Equal(t, 4*time.Hour, cfg.Assessment.MaxDuration)
	assert.Equal(t, int64(500000), cfg.Assessment.TokenBudget)
	assert.Equal(t, int32(20), cfg.Assessment.MaxIterations)
	assert.Equal(t, 24*time.Hour, cfg.Assessment.ReviewTimeout)
}

func TestDefaults_InfrastructureAllEmbedded(t *testing.T) {
	cfg := Defaults()
	infra := cfg.Infrastructure
	assert.False(t, infra.IsExternalPostgres())
	assert.False(t, infra.IsExternalNATS())
	assert.False(t, infra.IsExternalTemporal())
	assert.False(t, infra.IsExternalSPIRE())
	assert.False(t, infra.IsExternalVault())
	assert.False(t, infra.IsExternalFalco())
	assert.False(t, infra.IsExternalNomad())
}

func TestParse_InvalidYAML(t *testing.T) {
	_, err := Parse([]byte("{{invalid yaml"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parsing config")
}

func TestLoad_ValidFile(t *testing.T) {
	content := `
cages:
  discovery:
    max_duration: 45m
    max_vcpus: 8
    max_memory_mb: 16384
llm:
  endpoint: "https://api.example.com/v1"
timeouts:
  provision_vm: 60s
`
	path := writeTempFile(t, content)

	cfg, err := Load(path)
	require.NoError(t, err)
	require.NotNil(t, cfg)

	assert.Equal(t, 45*time.Minute, cfg.Cages["discovery"].MaxDuration)
	assert.Equal(t, int32(8), cfg.Cages["discovery"].MaxVCPUs)
	assert.Equal(t, int32(16384), cfg.Cages["discovery"].MaxMemoryMB)
	assert.Equal(t, "https://api.example.com/v1", cfg.LLM.Endpoint)
	assert.Equal(t, 60*time.Second, cfg.Timeouts.ProvisionVM)
}

func TestLoad_NonExistentFile(t *testing.T) {
	_, err := Load("/nonexistent/path/config.yaml")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "reading config file")
}

func TestLoad_InvalidYAML(t *testing.T) {
	path := writeTempFile(t, "{{invalid yaml")

	_, err := Load(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parsing config file")
}

func TestLoad_InfrastructureOverrides(t *testing.T) {
	content := `
infrastructure:
  postgres:
    url: "postgres://user:pass@prod-db:5432/agentcage"
  nats:
    url: "nats://prod-nats:4222"
  temporal:
    address: "temporal.prod:7233"
    tls:
      cert_file: /etc/agentcage/temporal.crt
      key_file: /etc/agentcage/temporal.key
  spire:
    server_address: "spire.prod:8081"
    trust_domain: "company.internal"
  vault:
    address: "https://vault.prod:8200"
    auth_path: "auth/jwt"
    role: "agentcage"
    tls:
      ca_cert_file: /etc/agentcage/vault-ca.pem
`
	path := writeTempFile(t, content)
	cfg, err := Load(path)
	require.NoError(t, err)

	assert.True(t, cfg.Infrastructure.IsExternalPostgres())
	assert.Equal(t, "postgres://user:pass@prod-db:5432/agentcage", cfg.Infrastructure.Postgres.URL)
	assert.True(t, cfg.Infrastructure.IsExternalNATS())
	assert.True(t, cfg.Infrastructure.IsExternalTemporal())
	assert.True(t, cfg.Infrastructure.IsExternalSPIRE())
	assert.Equal(t, "company.internal", cfg.Infrastructure.SPIRE.TrustDomain)
	assert.True(t, cfg.Infrastructure.IsExternalVault())
}

func TestMerge_PartialOverride(t *testing.T) {
	base := Defaults()
	override := &Config{
		Cages: map[string]CageTypeConfig{
			"discovery": {MaxVCPUs: 8},
		},
		Timeouts: ActivityTimeoutsConfig{
			ProvisionVM: 60 * time.Second,
		},
	}

	result := Merge(base, override)

	assert.Equal(t, int32(8), result.Cages["discovery"].MaxVCPUs)
	assert.Equal(t, 30*time.Minute, result.Cages["discovery"].MaxDuration, "unoverridden fields keep defaults")
	assert.Equal(t, int32(8192), result.Cages["discovery"].MaxMemoryMB, "unoverridden fields keep defaults")
	assert.Equal(t, 60*time.Second, result.Timeouts.ProvisionVM)
	assert.Equal(t, 5*time.Second, result.Timeouts.ValidateScope, "unoverridden timeouts keep defaults")
}

func TestMerge_NewCageType(t *testing.T) {
	base := Defaults()
	override := &Config{
		Cages: map[string]CageTypeConfig{
			"recon": {MaxDuration: 10 * time.Minute, MaxVCPUs: 2, MaxMemoryMB: 2048},
		},
	}

	result := Merge(base, override)
	require.Contains(t, result.Cages, "recon")
	assert.Equal(t, 10*time.Minute, result.Cages["recon"].MaxDuration)
	assert.Contains(t, result.Cages, "discovery", "existing cage types preserved")
}

func TestMerge_EmptyOverride(t *testing.T) {
	base := Defaults()
	override := &Config{}

	result := Merge(base, override)

	assert.Equal(t, base.LLM, result.LLM)
	assert.Equal(t, base.Timeouts, result.Timeouts)
	assert.Len(t, result.Cages, 3)
	assert.Len(t, result.Monitoring, 3)
	assert.Len(t, result.Payload, 7)
}

func TestMerge_DoesNotMutateBase(t *testing.T) {
	base := Defaults()
	originalVCPUs := base.Cages["discovery"].MaxVCPUs

	override := &Config{
		Cages: map[string]CageTypeConfig{
			"discovery": {MaxVCPUs: 16},
		},
	}

	_ = Merge(base, override)
	assert.Equal(t, originalVCPUs, base.Cages["discovery"].MaxVCPUs)
}

func TestMerge_InfrastructureOverride(t *testing.T) {
	base := Defaults()
	override := &Config{
		Infrastructure: InfrastructureConfig{
			Postgres: &PostgresConfig{URL: "postgres://prod:5432/ac"},
		},
	}

	result := Merge(base, override)
	assert.True(t, result.Infrastructure.IsExternalPostgres())
	assert.Equal(t, "postgres://prod:5432/ac", result.Infrastructure.Postgres.URL)
	assert.False(t, result.Infrastructure.IsExternalNATS(), "unset services stay embedded")
}

func TestMerge_LLMOverride(t *testing.T) {
	base := Defaults()
	override := &Config{
		LLM: LLMConfig{
			Endpoint: "https://api.anthropic.com/v1",
		},
	}

	result := Merge(base, override)
	assert.Equal(t, "https://api.anthropic.com/v1", result.LLM.Endpoint)
	assert.Equal(t, 30*time.Second, result.LLM.Timeout, "default timeout preserved")
}

func TestBlocklistPatterns(t *testing.T) {
	cfg := Defaults()
	patterns := cfg.BlocklistPatterns()
	require.Len(t, patterns, 7)
	assert.NotEmpty(t, patterns["sqli"])
	assert.NotEmpty(t, patterns["rce"])
	assert.NotEmpty(t, patterns["ssrf"])
	assert.NotEmpty(t, patterns["xss"])
	assert.NotEmpty(t, patterns["path_traversal"])
	assert.NotEmpty(t, patterns["xxe"])
	assert.NotEmpty(t, patterns["ldap_injection"])
}

func TestRateLimit(t *testing.T) {
	cfg := Defaults()
	assert.Equal(t, int32(1000), cfg.RateLimit("discovery"))
	assert.Equal(t, int32(100), cfg.RateLimit("validator"))
	assert.Equal(t, int32(500), cfg.RateLimit("escalation"))
	assert.Equal(t, int32(0), cfg.RateLimit("nonexistent"))
}

func writeTempFile(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "test-config.yaml")
	err := os.WriteFile(path, []byte(content), 0644)
	require.NoError(t, err)
	return path
}
