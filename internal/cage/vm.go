package cage

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
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
	CageID     string
	VCPUs      int32
	MemoryMB   int32
	RootfsPath string
	KernelPath string
}

type VMHandle struct {
	ID         string
	CageID     string
	IPAddress  string
	SocketPath string
	StartedAt  time.Time
}

type VMProvisioner interface {
	Provision(ctx context.Context, config VMConfig) (*VMHandle, error)
	Terminate(ctx context.Context, vmID string) error
	Status(ctx context.Context, vmID string) (VMStatus, error)
	PauseVM(ctx context.Context, vmID string) error
	ResumeVM(ctx context.Context, vmID string) error
}

// MockProvisioner is an in-memory VM provisioner for tests and CI
// environments without KVM. It tracks VM state in maps but does not
// create real VMs. The real provisioner is FirecrackerProvisioner.
type MockProvisioner struct {
	mu     sync.Mutex
	vms    map[string]*VMHandle
	paused map[string]bool
	// byCageID enables idempotent provisioning: if a cage already
	// has a VM, we return the existing handle instead of creating a duplicate.
	byCageID map[string]string
}

func NewMockProvisioner() *MockProvisioner {
	return &MockProvisioner{
		vms:      make(map[string]*VMHandle),
		paused:   make(map[string]bool),
		byCageID: make(map[string]string),
	}
}

func (p *MockProvisioner) Provision(ctx context.Context, config VMConfig) (*VMHandle, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if vmID, ok := p.byCageID[config.CageID]; ok {
		return p.vms[vmID], nil
	}

	id := uuid.New().String()
	handle := &VMHandle{
		ID:         id,
		CageID:     config.CageID,
		IPAddress:  fmt.Sprintf("172.20.0.%d", len(p.vms)+2),
		SocketPath: fmt.Sprintf("/tmp/firecracker/%s.sock", id),
		StartedAt:  time.Now(),
	}
	p.vms[id] = handle
	p.byCageID[config.CageID] = id
	return handle, nil
}

func (p *MockProvisioner) Terminate(_ context.Context, vmID string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	handle, ok := p.vms[vmID]
	if !ok {
		return nil
	}
	delete(p.byCageID, handle.CageID)
	delete(p.vms, vmID)
	return nil
}

func (p *MockProvisioner) Status(_ context.Context, vmID string) (VMStatus, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if _, ok := p.vms[vmID]; ok {
		return VMStatusRunning, nil
	}
	return VMStatusStopped, nil
}

func (p *MockProvisioner) PauseVM(_ context.Context, vmID string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if _, ok := p.vms[vmID]; !ok {
		return fmt.Errorf("VM %s not found", vmID)
	}
	p.paused[vmID] = true
	return nil
}

func (p *MockProvisioner) ResumeVM(_ context.Context, vmID string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if _, ok := p.vms[vmID]; !ok {
		return fmt.Errorf("VM %s not found", vmID)
	}
	delete(p.paused, vmID)
	return nil
}
