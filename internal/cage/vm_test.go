package cage

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMockProvisioner_Provision(t *testing.T) {
	p := NewMockProvisioner()
	ctx := context.Background()

	handle, err := p.Provision(ctx, VMConfig{
		CageID:     "cage-1",
		VCPUs:      2,
		MemoryMB:   512,
		RootfsPath: "/rootfs",
		KernelPath: "/kernel",
	})
	require.NoError(t, err)
	assert.Equal(t, "cage-1", handle.CageID)
	assert.NotEmpty(t, handle.ID)
	assert.NotEmpty(t, handle.IPAddress)
	assert.NotEmpty(t, handle.SocketPath)
}

func TestMockProvisioner_ProvisionIdempotent(t *testing.T) {
	p := NewMockProvisioner()
	ctx := context.Background()
	cfg := VMConfig{CageID: "cage-1", VCPUs: 2, MemoryMB: 512}

	first, err := p.Provision(ctx, cfg)
	require.NoError(t, err)

	second, err := p.Provision(ctx, cfg)
	require.NoError(t, err)

	assert.Equal(t, first.ID, second.ID)
}

func TestMockProvisioner_Terminate(t *testing.T) {
	p := NewMockProvisioner()
	ctx := context.Background()

	handle, err := p.Provision(ctx, VMConfig{CageID: "cage-1"})
	require.NoError(t, err)

	err = p.Terminate(ctx, handle.ID)
	require.NoError(t, err)

	status, err := p.Status(ctx, handle.ID)
	require.NoError(t, err)
	assert.Equal(t, VMStatusStopped, status)
}

func TestMockProvisioner_TerminateNonExistent(t *testing.T) {
	p := NewMockProvisioner()
	err := p.Terminate(context.Background(), "nonexistent-vm")
	require.NoError(t, err)
}

func TestMockProvisioner_StatusRunning(t *testing.T) {
	p := NewMockProvisioner()
	ctx := context.Background()

	handle, err := p.Provision(ctx, VMConfig{CageID: "cage-1"})
	require.NoError(t, err)

	status, err := p.Status(ctx, handle.ID)
	require.NoError(t, err)
	assert.Equal(t, VMStatusRunning, status)
}

func TestMockProvisioner_StatusUnknownVM(t *testing.T) {
	p := NewMockProvisioner()
	status, err := p.Status(context.Background(), "unknown-vm")
	require.NoError(t, err)
	assert.Equal(t, VMStatusStopped, status)
}
