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
	Provision(ctx context.Context, config VMConfig) (*VMHandle, error)
	Terminate(ctx context.Context, vmID string) error
	Status(ctx context.Context, vmID string) (VMStatus, error)
	PauseVM(ctx context.Context, vmID string) error
	ResumeVM(ctx context.Context, vmID string) error
}


