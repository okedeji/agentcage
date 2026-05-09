package cage

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/go-logr/logr"
	"github.com/google/uuid"
)

// FirecrackerProvisioner manages Firecracker microVMs on the local host.
// Each cage gets its own Firecracker process, TAP device, and rootfs copy.
type FirecrackerProvisioner struct {
	mu         sync.Mutex
	vms        map[string]*firecrackerVM
	byCageID   map[string]string
	binPath    string
	kernelPath string
	logDir     string
	log        logr.Logger
}

type firecrackerVM struct {
	handle  *VMHandle
	cmd     *exec.Cmd
	tapName string
}

// FirecrackerConfig holds paths needed by the provisioner.
type FirecrackerConfig struct {
	BinPath    string // path to firecracker binary
	KernelPath string // path to vmlinux kernel
	LogDir     string // shared directory for cage console logs (readable from host)
}

func NewFirecrackerProvisioner(cfg FirecrackerConfig, log logr.Logger) *FirecrackerProvisioner {
	return &FirecrackerProvisioner{
		vms:        make(map[string]*firecrackerVM),
		byCageID:   make(map[string]string),
		binPath:    cfg.BinPath,
		kernelPath: cfg.KernelPath,
		logDir:     cfg.LogDir,
		log:        log.WithValues("component", "firecracker-provisioner"),
	}
}

// SweepStale removes leftover Firecracker API sockets and TAP devices from a
// previous orchestrator run that did not shut down cleanly. Safe to call at
// startup before any cages are provisioned.
func (p *FirecrackerProvisioner) SweepStale(ctx context.Context) error {
	socketDir := filepath.Join(os.TempDir(), "firecracker")
	entries, err := os.ReadDir(socketDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("listing %s: %w", socketDir, err)
	}

	var swept int
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if strings.HasSuffix(name, ".vsock") {
			_ = os.Remove(filepath.Join(socketDir, name))
			continue
		}
		// Sockets are named "<vmID>.sock". Derive the matching tap name.
		if !strings.HasSuffix(name, ".sock") {
			continue
		}
		vmID := strings.TrimSuffix(name, ".sock")
		if len(vmID) >= 8 {
			tapName := fmt.Sprintf("tap-%s", vmID[:8])
			_ = teardownTAP(ctx, tapName)
		}
		_ = os.Remove(filepath.Join(socketDir, name))
		swept++
	}
	if swept > 0 {
		p.log.Info("swept stale firecracker state", "sockets", swept, "dir", socketDir)
	}
	return nil
}

func (p *FirecrackerProvisioner) Provision(ctx context.Context, config VMConfig) (*VMHandle, error) {
	p.mu.Lock()
	// Idempotent: return existing VM for this cage
	if vmID, ok := p.byCageID[config.CageID]; ok {
		handle := p.vms[vmID].handle
		p.mu.Unlock()
		return handle, nil
	}
	p.mu.Unlock()

	vmID := uuid.New().String()
	socketPath := filepath.Join(os.TempDir(), "firecracker", vmID+".sock")

	if err := os.MkdirAll(filepath.Dir(socketPath), 0755); err != nil {
		return nil, fmt.Errorf("creating socket directory: %w", err)
	}

	// Set up TAP device for this VM
	tapName := fmt.Sprintf("tap-%s", vmID[:8])
	ipAddr, ipErr := p.allocateIP()
	if ipErr != nil {
		return nil, ipErr
	}

	if err := setupTAP(ctx, tapName, ipAddr); err != nil {
		return nil, fmt.Errorf("setting up TAP device %s: %w", tapName, err)
	}

	// Use the config rootfs path; assembled rootfs is the fallback.
	rootfsPath := config.RootfsPath
	kernelPath := config.KernelPath
	if kernelPath == "" {
		kernelPath = p.kernelPath
	}

	// Start Firecracker process
	// Write to shared log directory so the operator can read it
	// from the host via `agentcage logs firecracker`.
	logDir := filepath.Join(os.TempDir(), "firecracker")
	if p.logDir != "" {
		logDir = p.logDir
	}
	fcLogFile := filepath.Join(logDir, "firecracker-vmm.log")
	serialFile := filepath.Join(logDir, "firecracker.log")

	cmd := exec.CommandContext(ctx, p.binPath,
		"--api-sock", socketPath,
		"--log-path", fcLogFile,
		"--level", "Trace",
		"--show-level",
		"--show-log-origin",
	)
	if f, err := os.OpenFile(serialFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644); err == nil {
		cmd.Stdout = f
		cmd.Stderr = f
	} else {
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
	}

	p.log.Info("starting firecracker",
		"cage_id", config.CageID,
		"vm_id", vmID,
		"vcpus", config.VCPUs,
		"memory_mb", config.MemoryMB,
	)

	cleanup := func() {
		_ = teardownTAP(context.Background(), tapName)
		_ = os.Remove(socketPath)
	}

	if err := cmd.Start(); err != nil {
		cleanup()
		return nil, fmt.Errorf("starting firecracker process: %w", err)
	}

	if err := waitForSocket(ctx, socketPath, 5*time.Second); err != nil {
		_ = cmd.Process.Kill()
		cleanup()
		return nil, fmt.Errorf("waiting for firecracker API socket: %w", err)
	}

	if err := p.configureVM(ctx, socketPath, kernelPath, rootfsPath, config, tapName); err != nil {
		_ = cmd.Process.Kill()
		cleanup()
		return nil, fmt.Errorf("configuring VM: %w", err)
	}

	if err := p.startVM(ctx, socketPath); err != nil {
		_ = cmd.Process.Kill()
		cleanup()
		return nil, fmt.Errorf("starting VM instance: %w", err)
	}

	vsockPath := strings.TrimSuffix(socketPath, ".sock") + ".vsock"
	handle := &VMHandle{
		ID:         vmID,
		CageID:     config.CageID,
		IPAddress:  ipAddr,
		SocketPath: socketPath,
		VsockPath:  vsockPath,
		StartedAt:  time.Now(),
	}

	p.mu.Lock()
	p.vms[vmID] = &firecrackerVM{
		handle:  handle,
		cmd:     cmd,
		tapName: tapName,
	}
	p.byCageID[config.CageID] = vmID
	p.mu.Unlock()

	p.log.Info("cage VM running",
		"cage_id", config.CageID,
		"vm_id", vmID,
		"ip", ipAddr,
	)

	return handle, nil
}

func (p *FirecrackerProvisioner) Terminate(ctx context.Context, vmID string) error {
	p.mu.Lock()
	vm, ok := p.vms[vmID]
	if !ok {
		p.mu.Unlock()
		return nil
	}
	delete(p.byCageID, vm.handle.CageID)
	delete(p.vms, vmID)
	p.mu.Unlock()

	var errs []error

	// Stop the Firecracker process
	if vm.cmd != nil && vm.cmd.Process != nil {
		if err := vm.cmd.Process.Kill(); err != nil {
			errs = append(errs, fmt.Errorf("killing firecracker process: %w", err))
		}
		_ = vm.cmd.Wait() // best-effort reap
	}

	// Clean up TAP device
	if err := teardownTAP(ctx, vm.tapName); err != nil {
		errs = append(errs, fmt.Errorf("tearing down TAP device: %w", err))
	}

	// Clean up sockets
	_ = os.Remove(vm.handle.SocketPath)
	_ = os.Remove(vm.handle.VsockPath)

	p.log.Info("cage VM terminated", "vm_id", vmID, "cage_id", vm.handle.CageID)

	if len(errs) > 0 {
		return fmt.Errorf("terminate errors: %v", errs)
	}
	return nil
}

func (p *FirecrackerProvisioner) Status(_ context.Context, vmID string) (VMStatus, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	vm, ok := p.vms[vmID]
	if !ok {
		return VMStatusStopped, nil
	}

	// Check if process is still alive
	if vm.cmd != nil && vm.cmd.ProcessState != nil && vm.cmd.ProcessState.Exited() {
		return VMStatusStopped, nil
	}
	return VMStatusRunning, nil
}

func (p *FirecrackerProvisioner) PauseVM(ctx context.Context, vmID string) error {
	p.mu.Lock()
	vm, ok := p.vms[vmID]
	p.mu.Unlock()

	if !ok {
		return fmt.Errorf("VM %s not found", vmID)
	}
	if err := firecrackerAPI(ctx, vm.handle.SocketPath, "PATCH", "/vm", map[string]any{"state": "Paused"}); err != nil {
		return fmt.Errorf("VM %s (cage %s): pausing: %w", vmID, vm.handle.CageID, err)
	}
	return nil
}

func (p *FirecrackerProvisioner) ResumeVM(ctx context.Context, vmID string) error {
	p.mu.Lock()
	vm, ok := p.vms[vmID]
	p.mu.Unlock()

	if !ok {
		return fmt.Errorf("VM %s not found", vmID)
	}
	if err := firecrackerAPI(ctx, vm.handle.SocketPath, "PATCH", "/vm", map[string]any{"state": "Resumed"}); err != nil {
		return fmt.Errorf("VM %s (cage %s): resuming: %w", vmID, vm.handle.CageID, err)
	}
	return nil
}

// configureVM sends boot source, drives, machine config, and network config
// to the Firecracker API.
func (p *FirecrackerProvisioner) configureVM(ctx context.Context, socket, kernelPath, rootfsPath string, cfg VMConfig, tapName string) error {
	// Set boot source
	bootArgs := "console=ttyS0 reboot=k panic=1 pci=off"
	if runtime.GOARCH == "arm64" {
		bootArgs = "earlycon=uart,mmio,0x40002000 " + bootArgs
	}
	bootSource := map[string]any{
		"kernel_image_path": kernelPath,
		"boot_args":         bootArgs,
	}
	if err := firecrackerAPI(ctx, socket, "PUT", "/boot-source", bootSource); err != nil {
		return fmt.Errorf("setting boot source: %w", err)
	}

	// Set root drive
	drive := map[string]any{
		"drive_id":       "rootfs",
		"path_on_host":  rootfsPath,
		"is_root_device": true,
		"is_read_only":  false,
	}
	if err := firecrackerAPI(ctx, socket, "PUT", "/drives/rootfs", drive); err != nil {
		return fmt.Errorf("setting root drive: %w", err)
	}

	// Set machine config
	machine := map[string]any{
		"vcpu_count":  cfg.VCPUs,
		"mem_size_mib": cfg.MemoryMB,
	}
	if err := firecrackerAPI(ctx, socket, "PUT", "/machine-config", machine); err != nil {
		return fmt.Errorf("setting machine config: %w", err)
	}

	// Set network interface
	network := map[string]any{
		"iface_id":      "eth0",
		"host_dev_name": tapName,
		"guest_mac":     generateMAC(cfg.CageID),
	}
	if err := firecrackerAPI(ctx, socket, "PUT", "/network-interfaces/eth0", network); err != nil {
		return fmt.Errorf("setting network interface: %w", err)
	}

	// Vsock enables bidirectional host↔guest communication for
	// directives, agent-initiated holds, and log forwarding without
	// touching the network stack or mounting the rootfs from outside.
	vsockUDS := strings.TrimSuffix(socket, ".sock") + ".vsock"
	vsock := map[string]any{
		"guest_cid": 3,
		"uds_path":  vsockUDS,
	}
	if err := firecrackerAPI(ctx, socket, "PUT", "/vsock", vsock); err != nil {
		return fmt.Errorf("setting vsock device: %w", err)
	}

	return nil
}

// startVM tells Firecracker to boot the configured VM.
func (p *FirecrackerProvisioner) startVM(ctx context.Context, socket string) error {
	action := map[string]any{
		"action_type": "InstanceStart",
	}
	return firecrackerAPI(ctx, socket, "PUT", "/actions", action)
}

// firecrackerAPI sends an HTTP request to the Firecracker API via Unix socket.
func firecrackerAPI(ctx context.Context, socketPath, method, path string, body any) error {
	payload, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshaling request: %w", err)
	}

	transport := &http.Transport{
		DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
			return net.Dial("unix", socketPath)
		},
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport}

	req, err := http.NewRequestWithContext(ctx, method, "http://localhost"+path, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("sending request to %s: %w", path, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 400 {
		var errBody bytes.Buffer
		_, _ = errBody.ReadFrom(resp.Body)
		return fmt.Errorf("firecracker API %s %s: status %d: %s", method, path, resp.StatusCode, errBody.String())
	}

	return nil
}

// setupTAP creates a TAP device and assigns an IP for host-side networking.
func setupTAP(ctx context.Context, tapName, ipAddr string) error {
	commands := [][]string{
		{"ip", "tuntap", "add", "dev", tapName, "mode", "tap"},
		{"ip", "addr", "add", ipAddr + "/30", "dev", tapName},
		{"ip", "link", "set", tapName, "up"},
	}
	for _, args := range commands {
		cmd := exec.CommandContext(ctx, args[0], args[1:]...)
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("running %v: %w\n%s", args, err, out)
		}
	}
	return nil
}

// teardownTAP removes a TAP device.
func teardownTAP(ctx context.Context, tapName string) error {
	cmd := exec.CommandContext(ctx, "ip", "link", "delete", tapName)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("deleting tap %s: %w\n%s", tapName, err, out)
	}
	return nil
}

func waitForSocket(ctx context.Context, path string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
	return fmt.Errorf("socket %s did not appear within %s", path, timeout)
}

var ipCounter uint32 = 1
var ipMu sync.Mutex

func (p *FirecrackerProvisioner) allocateIP() (string, error) {
	ipMu.Lock()
	defer ipMu.Unlock()
	ipCounter++
	third := ipCounter / 252
	fourth := (ipCounter % 252) + 2
	if third > 255 {
		return "", fmt.Errorf("IP address space exhausted (172.20.0.0/16, %d VMs allocated)", ipCounter)
	}
	return fmt.Sprintf("172.20.%d.%d", third, fourth), nil
}

func generateMAC(cageID string) string {
	// Deterministic MAC from cage ID for reproducibility.
	// Use locally-administered unicast prefix (02:xx:xx:xx:xx:xx).
	h := []byte(cageID)
	if len(h) < 5 {
		h = append(h, make([]byte, 5-len(h))...)
	}
	return fmt.Sprintf("02:%02x:%02x:%02x:%02x:%02x", h[0], h[1], h[2], h[3], h[4])
}
