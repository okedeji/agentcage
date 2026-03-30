package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func loadEmbeddedYAML(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "agentcage.yaml"))
	require.NoError(t, err)
	return data
}

func testDefault(t *testing.T) *Config {
	t.Helper()
	cfg, err := Default(loadEmbeddedYAML(t))
	require.NoError(t, err)
	return cfg
}

func TestDefault_ReturnsPopulatedConfig(t *testing.T) {
	cfg := testDefault(t)
	require.NotNil(t, cfg)
	assert.NotEmpty(t, cfg.CageTypes)
	assert.NotEmpty(t, cfg.TripwirePolicies)
	assert.NotEmpty(t, cfg.BlocklistPatterns)
	assert.NotEmpty(t, cfg.Infrastructure.InfraHosts)
}

func TestDefault_HasThreeCageTypes(t *testing.T) {
	cfg := testDefault(t)
	require.Len(t, cfg.CageTypes, 3)

	disc := cfg.CageTypes["discovery"]
	assert.Equal(t, 30*time.Minute, disc.MaxDuration)
	assert.Equal(t, int32(4), disc.MaxVCPUs)
	assert.Equal(t, int32(8192), disc.MaxMemoryMB)

	val := cfg.CageTypes["validator"]
	assert.Equal(t, 60*time.Second, val.MaxDuration)
	assert.Equal(t, int32(1), val.MaxVCPUs)
	assert.Equal(t, int32(1024), val.MaxMemoryMB)

	esc := cfg.CageTypes["escalation"]
	assert.Equal(t, 15*time.Minute, esc.MaxDuration)
	assert.Equal(t, int32(2), esc.MaxVCPUs)
	assert.Equal(t, int32(4096), esc.MaxMemoryMB)
}

func TestDefault_HasAllActivityTimeouts(t *testing.T) {
	cfg := testDefault(t)
	at := cfg.ActivityTimeouts

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

func TestDefault_HasThreeTripwirePolicySets(t *testing.T) {
	cfg := testDefault(t)
	require.Len(t, cfg.TripwirePolicies, 3)
	assert.Contains(t, cfg.TripwirePolicies, "discovery")
	assert.Contains(t, cfg.TripwirePolicies, "validator")
	assert.Contains(t, cfg.TripwirePolicies, "escalation")
}

func TestDefault_HasFourBlocklistPatternSets(t *testing.T) {
	cfg := testDefault(t)
	require.Len(t, cfg.BlocklistPatterns, 4)
	assert.Contains(t, cfg.BlocklistPatterns, "sqli")
	assert.Contains(t, cfg.BlocklistPatterns, "rce")
	assert.Contains(t, cfg.BlocklistPatterns, "ssrf")
	assert.Contains(t, cfg.BlocklistPatterns, "xss")
}

func TestDefault_InvalidYAML(t *testing.T) {
	_, err := Default([]byte("{{invalid yaml"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parsing embedded default config")
}

func TestLoad_ValidFile(t *testing.T) {
	content := `
cage_types:
  discovery:
    max_duration: 45m
    max_vcpus: 8
    max_memory_mb: 16384
rate_limits:
  max_requests_per_second: 500
activity_timeouts:
  provision_vm: 60s
infrastructure:
  llm_endpoint: custom-llm.example.com
`
	path := writeTempFile(t, content)

	cfg, err := Load(path)
	require.NoError(t, err)
	require.NotNil(t, cfg)

	assert.Equal(t, 45*time.Minute, cfg.CageTypes["discovery"].MaxDuration)
	assert.Equal(t, int32(8), cfg.CageTypes["discovery"].MaxVCPUs)
	assert.Equal(t, int32(16384), cfg.CageTypes["discovery"].MaxMemoryMB)
	assert.Equal(t, int32(500), cfg.RateLimits.MaxRequestsPerSecond)
	assert.Equal(t, 60*time.Second, cfg.ActivityTimeouts.ProvisionVM)
	assert.Equal(t, "custom-llm.example.com", cfg.Infrastructure.LLMEndpoint)
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

func TestMerge_PartialOverride(t *testing.T) {
	base := testDefault(t)
	override := &Config{
		CageTypes: map[string]CageTypeConfig{
			"discovery": {MaxVCPUs: 8},
		},
		ActivityTimeouts: ActivityTimeoutsConfig{
			ProvisionVM: 60 * time.Second,
		},
	}

	result := Merge(base, override)

	assert.Equal(t, int32(8), result.CageTypes["discovery"].MaxVCPUs)
	assert.Equal(t, 30*time.Minute, result.CageTypes["discovery"].MaxDuration, "unoverridden fields keep defaults")
	assert.Equal(t, int32(8192), result.CageTypes["discovery"].MaxMemoryMB, "unoverridden fields keep defaults")
	assert.Equal(t, 60*time.Second, result.ActivityTimeouts.ProvisionVM)
	assert.Equal(t, 5*time.Second, result.ActivityTimeouts.ValidateScope, "unoverridden timeouts keep defaults")
}

func TestMerge_NewCageType(t *testing.T) {
	base := testDefault(t)
	override := &Config{
		CageTypes: map[string]CageTypeConfig{
			"recon": {MaxDuration: 10 * time.Minute, MaxVCPUs: 2, MaxMemoryMB: 2048},
		},
	}

	result := Merge(base, override)
	require.Contains(t, result.CageTypes, "recon")
	assert.Equal(t, 10*time.Minute, result.CageTypes["recon"].MaxDuration)
	assert.Contains(t, result.CageTypes, "discovery", "existing cage types preserved")
}

func TestMerge_EmptyOverride(t *testing.T) {
	base := testDefault(t)
	override := &Config{}

	result := Merge(base, override)

	assert.Equal(t, base.RateLimits, result.RateLimits)
	assert.Equal(t, base.ActivityTimeouts, result.ActivityTimeouts)
	assert.Equal(t, base.Infrastructure.LLMEndpoint, result.Infrastructure.LLMEndpoint)
	assert.Len(t, result.CageTypes, 3)
	assert.Len(t, result.TripwirePolicies, 3)
	assert.Len(t, result.BlocklistPatterns, 4)
}

func TestMerge_DoesNotMutateBase(t *testing.T) {
	base := testDefault(t)
	originalVCPUs := base.CageTypes["discovery"].MaxVCPUs

	override := &Config{
		CageTypes: map[string]CageTypeConfig{
			"discovery": {MaxVCPUs: 16},
		},
	}

	_ = Merge(base, override)
	assert.Equal(t, originalVCPUs, base.CageTypes["discovery"].MaxVCPUs)
}

func writeTempFile(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "test-config.yaml")
	err := os.WriteFile(path, []byte(content), 0644)
	require.NoError(t, err)
	return path
}
