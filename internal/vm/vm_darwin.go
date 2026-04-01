//go:build darwin

package vm

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/Code-Hex/vz/v3"
)

// LinuxVM manages a lightweight Linux VM on macOS via Apple Virtualization.framework.
type LinuxVM struct {
	machine *vz.VirtualMachine
	ip      string
	mu      sync.Mutex
}

// Boot creates and starts a Linux VM with the given configuration.
func Boot(ctx context.Context, cfg Config) (*LinuxVM, error) {
	bootLoader, err := vz.NewLinuxBootLoader(cfg.KernelPath,
		vz.WithCommandLine("console=hvc0 root=/dev/vda rw init=/sbin/init-agentcage"),
	)
	if err != nil {
		return nil, fmt.Errorf("creating boot loader: %w", err)
	}

	vmCfg, err := vz.NewVirtualMachineConfiguration(bootLoader, uint(cfg.VCPUs), uint64(cfg.MemoryMB)*1024*1024)
	if err != nil {
		return nil, fmt.Errorf("creating VM config: %w", err)
	}

	// Disk (rootfs)
	diskAttachment, err := vz.NewDiskImageStorageDeviceAttachment(cfg.RootfsPath, false)
	if err != nil {
		return nil, fmt.Errorf("creating disk attachment: %w", err)
	}
	blockDevice, err := vz.NewVirtioBlockDeviceConfiguration(diskAttachment)
	if err != nil {
		return nil, fmt.Errorf("creating block device: %w", err)
	}
	vmCfg.SetStorageDevicesVirtualMachineConfiguration([]vz.StorageDeviceConfiguration{blockDevice})

	// Network (NAT)
	natAttachment, err := vz.NewNATNetworkDeviceAttachment()
	if err != nil {
		return nil, fmt.Errorf("creating NAT attachment: %w", err)
	}
	netDevice, err := vz.NewVirtioNetworkDeviceConfiguration(natAttachment)
	if err != nil {
		return nil, fmt.Errorf("creating network device: %w", err)
	}
	mac, err := vz.NewRandomLocallyAdministeredMACAddress()
	if err != nil {
		return nil, fmt.Errorf("creating MAC address: %w", err)
	}
	netDevice.SetMACAddress(mac)
	vmCfg.SetNetworkDevicesVirtualMachineConfiguration([]*vz.VirtioNetworkDeviceConfiguration{netDevice})

	// VirtioFS (shared directory)
	shareDevice, err := configureVirtioFS(cfg.ShareDir, cfg.ShareTag)
	if err != nil {
		return nil, fmt.Errorf("configuring VirtioFS: %w", err)
	}
	if shareDevice != nil {
		vmCfg.SetDirectorySharingDevicesVirtualMachineConfiguration([]vz.DirectorySharingDeviceConfiguration{shareDevice})
	}

	// Serial console
	serialPort, err := vz.NewVirtioConsoleDeviceSerialPortConfiguration(nil)
	if err != nil {
		return nil, fmt.Errorf("creating serial port: %w", err)
	}
	vmCfg.SetSerialPortsVirtualMachineConfiguration([]*vz.VirtioConsoleDeviceSerialPortConfiguration{serialPort})

	// Entropy
	entropyDevice, err := vz.NewVirtioEntropyDeviceConfiguration()
	if err != nil {
		return nil, fmt.Errorf("creating entropy device: %w", err)
	}
	vmCfg.SetEntropyDevicesVirtualMachineConfiguration([]*vz.VirtioEntropyDeviceConfiguration{entropyDevice})

	// Memory balloon
	balloonDevice, err := vz.NewVirtioTraditionalMemoryBalloonDeviceConfiguration()
	if err != nil {
		return nil, fmt.Errorf("creating memory balloon: %w", err)
	}
	vmCfg.SetMemoryBalloonDevicesVirtualMachineConfiguration([]vz.MemoryBalloonDeviceConfiguration{balloonDevice})

	validated, err := vmCfg.Validate()
	if err != nil {
		return nil, fmt.Errorf("validating VM config: %w", err)
	}
	if !validated {
		return nil, fmt.Errorf("VM configuration is invalid")
	}

	machine, err := vz.NewVirtualMachine(vmCfg)
	if err != nil {
		return nil, fmt.Errorf("creating virtual machine: %w", err)
	}

	v := &LinuxVM{machine: machine}

	if err := machine.Start(); err != nil {
		return nil, fmt.Errorf("starting VM: %w", err)
	}

	if err := v.waitForGRPC(ctx); err != nil {
		_ = v.Shutdown(context.Background())
		return nil, fmt.Errorf("VM did not become ready: %w", err)
	}

	return v, nil
}

func (v *LinuxVM) Shutdown(ctx context.Context) error {
	if v.machine == nil {
		return nil
	}
	canStop, err := v.machine.RequestStop()
	if err != nil || !canStop {
		return v.machine.Stop()
	}

	select {
	case newState := <-v.machine.StateChangedNotify():
		if newState == vz.VirtualMachineStateStopped {
			return nil
		}
		return v.machine.Stop()
	case <-ctx.Done():
		return v.machine.Stop()
	case <-time.After(10 * time.Second):
		return v.machine.Stop()
	}
}

func (v *LinuxVM) IP() string {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.ip
}

func (v *LinuxVM) IsRunning() bool {
	return v.machine != nil && v.machine.State() == vz.VirtualMachineStateRunning
}

func (v *LinuxVM) Wait() error {
	for newState := range v.machine.StateChangedNotify() {
		if newState == vz.VirtualMachineStateStopped {
			return nil
		}
	}
	return nil
}

func (v *LinuxVM) GRPCAddr() string {
	return net.JoinHostPort(v.IP(), fmt.Sprintf("%d", grpcPort))
}

// waitForGRPC polls the VM's gRPC port until it accepts connections.
func (v *LinuxVM) waitForGRPC(ctx context.Context) error {
	candidates := []string{
		"192.168.64.2",
		"192.168.64.3",
		"192.168.64.4",
		"192.168.64.5",
		"192.168.64.6",
		"192.168.64.7",
		"192.168.64.8",
	}

	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		for _, ip := range candidates {
			addr := net.JoinHostPort(ip, fmt.Sprintf("%d", grpcPort))
			conn, err := net.DialTimeout("tcp", addr, 1*time.Second)
			if err == nil {
				_ = conn.Close()
				v.mu.Lock()
				v.ip = ip
				v.mu.Unlock()
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
	return fmt.Errorf("gRPC not reachable after 90s on any candidate IP")
}

func configureVirtioFS(shareDir, tag string) (*vz.VirtioFileSystemDeviceConfiguration, error) {
	sharedDir, err := vz.NewSharedDirectory(shareDir, false)
	if err != nil {
		return nil, fmt.Errorf("creating shared directory: %w", err)
	}
	share, err := vz.NewSingleDirectoryShare(sharedDir)
	if err != nil {
		return nil, fmt.Errorf("creating directory share: %w", err)
	}
	device, err := vz.NewVirtioFileSystemDeviceConfiguration(tag)
	if err != nil {
		return nil, fmt.Errorf("creating VirtioFS device: %w", err)
	}
	device.SetDirectoryShare(share)
	return device, nil
}
