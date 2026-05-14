package cage

import (
	"context"
	"time"
)

type VMStatus int

const (
	VMStatusUnknown VMStatus = iota
	VMStatusRunning
	VMStatusStopped
)

func (s VMStatus) String() string {
	switch s {
	case VMStatusRunning:
		return "running"
	case VMStatusStopped:
		return "stopped"
	default:
		return "unknown"
	}
}

type VMConfig struct {
	CageID       string
	AssessmentID string
	VCPUs        int32
	MemoryMB     int32
	RootfsPath   string
	KernelPath   string
}

type VMHandle struct {
	ID         string
	CageID     string
	IPAddress  string
	SocketPath string
	VsockPath  string
	StartedAt  time.Time
}

type VMProvisioner interface {
	// Provision creates and configures a Firecracker VM but does not
	// boot it. The returned handle contains VsockPath so the caller
	// can create host-side listeners before the guest dials.
	Provision(ctx context.Context, config VMConfig) (*VMHandle, error)
	// StartVM boots a previously provisioned VM.
	StartVM(ctx context.Context, vmID string) error
	Terminate(ctx context.Context, vmID string) error
	Status(ctx context.Context, vmID string) (VMStatus, error)
	PauseVM(ctx context.Context, vmID string) error
	ResumeVM(ctx context.Context, vmID string) error
}


