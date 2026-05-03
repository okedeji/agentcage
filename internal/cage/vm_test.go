package cage

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestVMProvisioner_Interface(t *testing.T) {
	// Verify the interface is satisfied by FirecrackerProvisioner at compile time.
	var _ VMProvisioner = (*FirecrackerProvisioner)(nil)
}

func TestVMStatus_String(t *testing.T) {
	assert.Equal(t, "running", VMStatusRunning.String())
	assert.Equal(t, "stopped", VMStatusStopped.String())
	assert.Equal(t, "unknown", VMStatusUnknown.String())
}
