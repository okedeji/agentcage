package cage

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSubprocessProvisioner_Provision(t *testing.T) {
	// Use a non-existent binary — Provision will fail at Start but
	// we're testing the handle creation and idempotency logic.
	p := NewSubprocessProvisioner("/usr/bin/false", "/tmp")
	ctx := context.Background()

	handle, err := p.Provision(ctx, VMConfig{
		CageID:   "cage-1",
		VCPUs:    2,
		MemoryMB: 512,
	})
	// /bin/false will start and exit immediately, which is fine for
	// testing that the provisioner creates handles.
	require.NoError(t, err)
	assert.Equal(t, "cage-1", handle.CageID)
	assert.NotEmpty(t, handle.ID)
}

func TestSubprocessProvisioner_ProvisionIdempotent(t *testing.T) {
	p := NewSubprocessProvisioner("/usr/bin/false", "/tmp")
	ctx := context.Background()
	cfg := VMConfig{CageID: "cage-1", VCPUs: 2, MemoryMB: 512}

	first, err := p.Provision(ctx, cfg)
	require.NoError(t, err)

	second, err := p.Provision(ctx, cfg)
	require.NoError(t, err)

	assert.Equal(t, first.ID, second.ID)
}

func TestSubprocessProvisioner_Terminate(t *testing.T) {
	p := NewSubprocessProvisioner("/usr/bin/false", "/tmp")
	ctx := context.Background()

	handle, err := p.Provision(ctx, VMConfig{CageID: "cage-1"})
	require.NoError(t, err)

	err = p.Terminate(ctx, handle.ID)
	require.NoError(t, err)

	status, err := p.Status(ctx, handle.ID)
	require.NoError(t, err)
	assert.Equal(t, VMStatusStopped, status)
}

func TestSubprocessProvisioner_TerminateNonExistent(t *testing.T) {
	p := NewSubprocessProvisioner("/usr/bin/false", "/tmp")
	err := p.Terminate(context.Background(), "nonexistent-vm")
	require.NoError(t, err)
}

func TestSubprocessProvisioner_StatusAfterExit(t *testing.T) {
	// /bin/false exits immediately with code 1, so status should
	// report stopped after a brief wait.
	p := NewSubprocessProvisioner("/usr/bin/false", "/tmp")
	ctx := context.Background()

	handle, err := p.Provision(ctx, VMConfig{CageID: "cage-1"})
	require.NoError(t, err)

	// Give the process a moment to exit.
	// The background goroutine calls cmd.Wait() which sets ProcessState.
	for i := 0; i < 50; i++ {
		status, _ := p.Status(ctx, handle.ID)
		if status == VMStatusStopped {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("process did not exit within 500ms")
}
