package config

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testBaseConfig() *Config {
	return &Config{
		CageTypes: map[string]CageTypeConfig{
			"discovery": {
				MaxDuration: 1 * time.Hour,
				MaxVCPUs:    2,
				MaxMemoryMB: 512,
			},
			"validator": {
				MaxDuration: 30 * time.Minute,
				MaxVCPUs:    4,
				MaxMemoryMB: 1024,
			},
		},
		RateLimits: RateLimitsConfig{
			MaxRequestsPerSecond: 100,
		},
		ActivityTimeouts: ActivityTimeoutsConfig{
			ValidateScope: 5 * time.Second,
			ProvisionVM:   30 * time.Second,
		},
		Infrastructure: InfrastructureConfig{
			NATSAddr: "nats://localhost:4222",
		},
	}
}

func TestGetConfig(t *testing.T) {
	base := testBaseConfig()
	srv := NewConfigServer(base)

	got := srv.GetConfig(context.Background())
	assert.Equal(t, base, got)
}

func TestGetValue_KnownPath(t *testing.T) {
	srv := NewConfigServer(testBaseConfig())

	val, err := srv.GetValue(context.Background(), "cage_types.validator.max_vcpus")
	require.NoError(t, err)
	assert.Equal(t, "4", val)
}

func TestGetValue_TopLevel(t *testing.T) {
	srv := NewConfigServer(testBaseConfig())

	val, err := srv.GetValue(context.Background(), "infrastructure.nats_addr")
	require.NoError(t, err)
	assert.Equal(t, "nats://localhost:4222", val)
}

func TestGetValue_UnknownPath(t *testing.T) {
	srv := NewConfigServer(testBaseConfig())

	_, err := srv.GetValue(context.Background(), "cage_types.nonexistent.max_vcpus")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestUpdateValue(t *testing.T) {
	srv := NewConfigServer(testBaseConfig())
	ctx := context.Background()

	err := srv.UpdateValue(ctx, "infrastructure.nats_addr", "nats://prod:4222")
	require.NoError(t, err)

	val, err := srv.GetValue(ctx, "infrastructure.nats_addr")
	require.NoError(t, err)
	assert.Equal(t, "nats://prod:4222", val)
}

func TestUpdateValue_PreservesOtherFields(t *testing.T) {
	srv := NewConfigServer(testBaseConfig())
	ctx := context.Background()

	err := srv.UpdateValue(ctx, "infrastructure.nats_addr", "nats://prod:4222")
	require.NoError(t, err)

	cfg := srv.GetConfig(ctx)
	assert.Equal(t, int32(100), cfg.RateLimits.MaxRequestsPerSecond)
}

func TestResetConfig(t *testing.T) {
	srv := NewConfigServer(testBaseConfig())
	ctx := context.Background()

	err := srv.UpdateValue(ctx, "infrastructure.nats_addr", "nats://prod:4222")
	require.NoError(t, err)

	err = srv.ResetConfig(ctx)
	require.NoError(t, err)

	val, err := srv.GetValue(ctx, "infrastructure.nats_addr")
	require.NoError(t, err)
	assert.Equal(t, "nats://localhost:4222", val)
}

func TestConcurrentAccess(t *testing.T) {
	srv := NewConfigServer(testBaseConfig())
	ctx := context.Background()

	var wg sync.WaitGroup
	for range 50 {
		wg.Add(2)
		go func() {
			defer wg.Done()
			srv.GetConfig(ctx)
		}()
		go func() {
			defer wg.Done()
			_ = srv.UpdateValue(ctx, "infrastructure.nats_addr", "nats://concurrent:4222")
		}()
	}
	wg.Wait()
}
