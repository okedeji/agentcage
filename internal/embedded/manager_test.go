package embedded

import (
	"testing"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/okedeji/agentcage/internal/config"
)

func TestNewManager_DefaultConfig_AllEmbedded(t *testing.T) {
	cfg := config.Defaults()
	m := NewManager(cfg, logr.Discard(), "0.1.0")

	require.NotNil(t, m)
	// Postgres, NATS, Temporal, SPIRE, Vault, Falco, Firecracker, CageInternal = 8
	assert.Len(t, m.services, 8)

	names := make([]string, len(m.services))
	for i, svc := range m.services {
		names[i] = svc.Name()
	}
	assert.Contains(t, names, "postgres")
	assert.Contains(t, names, "nats")
	assert.Contains(t, names, "temporal")
	assert.Contains(t, names, "spire")
	assert.Contains(t, names, "vault")
	assert.Contains(t, names, "falco")
	assert.Contains(t, names, "firecracker")
}

func TestNewManager_ExternalPostgres_Excluded(t *testing.T) {
	cfg := config.Defaults()
	cfg.Infrastructure.Postgres = &config.PostgresConfig{
		External: true,
	}
	m := NewManager(cfg, logr.Discard(), "0.1.0")

	names := make([]string, len(m.services))
	for i, svc := range m.services {
		names[i] = svc.Name()
	}
	assert.NotContains(t, names, "postgres")
	assert.Contains(t, names, "nats")
}

func TestNewManager_ExternalAll_OnlyFirecracker(t *testing.T) {
	cfg := config.Defaults()
	cfg.Infrastructure = config.InfrastructureConfig{
		Postgres: &config.PostgresConfig{External: true},
		NATS:     &config.NATSConfig{External: true},
		Temporal: &config.TemporalConfig{Address: "ext:7233"},
		SPIRE:    &config.SPIREConfig{ServerAddress: "ext:8081"},
		Vault:    &config.VaultConfig{Address: "https://ext:8200"},
		Falco:    &config.FalcoConfig{Socket: "/run/falco.sock"},
	}
	m := NewManager(cfg, logr.Discard(), "0.1.0")

	// Firecracker + cage-internal downloaders remain (always embedded)
	assert.Len(t, m.services, 2)
	assert.Equal(t, "firecracker", m.services[0].Name())
	assert.Equal(t, "cage-internal", m.services[1].Name())
}

func TestServiceNames(t *testing.T) {
	log := logr.Discard()
	services := []Service{
		NewPostgresService(log),
		NewNATSService(log),
		NewTemporalService(log),
		NewSPIREService(log),
		NewVaultService(log),
		NewFalcoService(log, "0.1.0"),
		NewFirecrackerDownloader(log, "0.1.0"),
	}

	expected := []string{"postgres", "nats", "temporal", "spire", "vault", "falco", "firecracker"}
	for i, svc := range services {
		assert.Equal(t, expected[i], svc.Name())
		assert.False(t, svc.IsExternal())
	}
}

func TestNATSService_InProcess(t *testing.T) {
	svc := NewNATSService(logr.Discard())
	assert.Equal(t, "nats://localhost:14222", svc.URL())
	assert.Equal(t, "nats", svc.Name())
	assert.False(t, svc.IsExternal())
}

func TestPostgresService_URL(t *testing.T) {
	svc := NewPostgresService(logr.Discard())
	url := svc.URL()
	assert.Contains(t, url, "15432")
	assert.Contains(t, url, "agentcage")
}

func TestTemporalService_Address(t *testing.T) {
	svc := NewTemporalService(logr.Discard())
	assert.Equal(t, "localhost:17233", svc.Address())
}

func TestVaultService_Address(t *testing.T) {
	svc := NewVaultService(logr.Discard())
	assert.Equal(t, "http://localhost:18200", svc.Address())
}

func TestSPIREService_Socket(t *testing.T) {
	svc := NewSPIREService(logr.Discard())
	socket := svc.AgentSocket()
	assert.Contains(t, socket, "spire")
	assert.Contains(t, socket, "agent.sock")
}

func TestFirecrackerDownloader_Paths(t *testing.T) {
	dl := NewFirecrackerDownloader(logr.Discard(), "0.1.0")
	assert.Contains(t, dl.BinPath(), "firecracker")
	assert.Contains(t, dl.KernelPath(), "vmlinux")
}

func TestDataDir(t *testing.T) {
	config.SetHome("/tmp/test-agentcage")
	defer config.SetHome("")
	assert.Equal(t, "/tmp/test-agentcage", DataDir())
	assert.Equal(t, "/tmp/test-agentcage/bin", BinDir())
	assert.Equal(t, "/tmp/test-agentcage/logs", LogDir())
	assert.Equal(t, "/tmp/test-agentcage/run", RunDir())
	assert.Equal(t, "/tmp/test-agentcage/data/postgres", ServiceDataDir("postgres"))
}

func TestEnsureDirs(t *testing.T) {
	config.SetHome(t.TempDir())
	defer config.SetHome("")
	err := EnsureDirs()
	require.NoError(t, err)

	assert.DirExists(t, BinDir())
	assert.DirExists(t, LogDir())
	assert.DirExists(t, RunDir())
	assert.DirExists(t, ServiceDataDir("postgres"))
	assert.DirExists(t, ServiceDataDir("temporal"))
	assert.DirExists(t, ServiceDataDir("nats"))
	assert.DirExists(t, ServiceDataDir("spire"))
	assert.DirExists(t, ServiceDataDir("vault"))
}
