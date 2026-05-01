package cage

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
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

// SubprocessProvisioner runs cages as local processes instead of
// Firecracker microVMs. Same cage-init binary, same sidecars, same
// findings flow — only the isolation boundary is missing.
type SubprocessProvisioner struct {
	mu       sync.Mutex
	procs    map[string]*subprocessCage
	byCageID map[string]string
	// CageInitBin is the path to the cage-init binary.
	CageInitBin string
	// SidecarDir is where findings-sidecar, directive-sidecar,
	// payload-proxy binaries live.
	SidecarDir string
}

type subprocessCage struct {
	handle  *VMHandle
	cmd     *exec.Cmd
	workDir string
}

func NewSubprocessProvisioner(cageInitBin, sidecarDir string) *SubprocessProvisioner {
	return &SubprocessProvisioner{
		procs:       make(map[string]*subprocessCage),
		byCageID:    make(map[string]string),
		CageInitBin: cageInitBin,
		SidecarDir:  sidecarDir,
	}
}

func (p *SubprocessProvisioner) Provision(ctx context.Context, config VMConfig) (*VMHandle, error) {
	p.mu.Lock()
	if vmID, ok := p.byCageID[config.CageID]; ok {
		handle := p.procs[vmID].handle
		p.mu.Unlock()
		return handle, nil
	}
	p.mu.Unlock()

	id := uuid.New().String()
	workDir := filepath.Join(os.TempDir(), "agentcage-cage-"+id[:8])
	if err := os.MkdirAll(filepath.Join(workDir, "run"), 0755); err != nil {
		return nil, fmt.Errorf("creating cage work dir: %w", err)
	}

	// cage.json is written by AssembleRootfs in unisolated mode.
	// The config path is at workDir/cage.json.
	cmd := exec.CommandContext(ctx, p.CageInitBin)
	cmd.Env = append(os.Environ(),
		"AGENTCAGE_CAGE_CONFIG="+filepath.Join(workDir, "cage.json"),
		"AGENTCAGE_SOCKET_DIR="+filepath.Join(workDir, "run"),
		"AGENTCAGE_AGENT_DIR="+filepath.Join(workDir, "agent"),
		"AGENTCAGE_SIDECAR_DIR="+p.SidecarDir,
	)
	cmd.Dir = workDir

	// Log to a file in the work dir so cage logs are accessible.
	logFile, _ := os.OpenFile(filepath.Join(workDir, "cage.log"),
		os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	cmd.Stdout = logFile
	cmd.Stderr = logFile

	if err := cmd.Start(); err != nil {
		_ = os.RemoveAll(workDir)
		if logFile != nil {
			_ = logFile.Close()
		}
		return nil, fmt.Errorf("starting cage-init: %w", err)
	}

	handle := &VMHandle{
		ID:         id,
		CageID:     config.CageID,
		IPAddress:  "127.0.0.1",
		SocketPath: filepath.Join(workDir, "run", "findings.sock"),
		VsockPath:  "",
		StartedAt:  time.Now(),
	}

	cage := &subprocessCage{handle: handle, cmd: cmd, workDir: workDir}

	p.mu.Lock()
	p.procs[id] = cage
	p.byCageID[config.CageID] = id
	p.mu.Unlock()

	// Reap the process in background so Status can detect exit.
	go func() {
		_ = cmd.Wait()
		if logFile != nil {
			_ = logFile.Close()
		}
	}()

	return handle, nil
}

func (p *SubprocessProvisioner) Terminate(_ context.Context, vmID string) error {
	p.mu.Lock()
	cage, ok := p.procs[vmID]
	if !ok {
		p.mu.Unlock()
		return nil
	}
	delete(p.byCageID, cage.handle.CageID)
	delete(p.procs, vmID)
	p.mu.Unlock()

	if cage.cmd.Process != nil {
		_ = cage.cmd.Process.Signal(syscall.SIGTERM)
		time.AfterFunc(5*time.Second, func() {
			if cage.cmd.ProcessState == nil {
				_ = cage.cmd.Process.Kill()
			}
		})
	}
	_ = os.RemoveAll(cage.workDir)
	return nil
}

func (p *SubprocessProvisioner) Status(_ context.Context, vmID string) (VMStatus, error) {
	p.mu.Lock()
	cage, ok := p.procs[vmID]
	p.mu.Unlock()

	if !ok {
		return VMStatusStopped, nil
	}
	if cage.cmd.ProcessState != nil {
		return VMStatusStopped, nil
	}
	return VMStatusRunning, nil
}

func (p *SubprocessProvisioner) PauseVM(_ context.Context, vmID string) error {
	p.mu.Lock()
	cage, ok := p.procs[vmID]
	p.mu.Unlock()

	if !ok {
		return fmt.Errorf("cage %s not found", vmID)
	}
	if cage.cmd.Process != nil {
		return cage.cmd.Process.Signal(syscall.SIGSTOP)
	}
	return nil
}

func (p *SubprocessProvisioner) ResumeVM(_ context.Context, vmID string) error {
	p.mu.Lock()
	cage, ok := p.procs[vmID]
	p.mu.Unlock()

	if !ok {
		return fmt.Errorf("cage %s not found", vmID)
	}
	if cage.cmd.Process != nil {
		return cage.cmd.Process.Signal(syscall.SIGCONT)
	}
	return nil
}

