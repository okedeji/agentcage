//go:build darwin

package vm

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/Code-Hex/vz/v3"
)

// LinuxVM manages a lightweight Linux VM on macOS via Apple Virtualization.framework.
type LinuxVM struct {
	machine        *vz.VirtualMachine
	ip             string
	mu             sync.Mutex
	consoleLogPath string
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

	// Copy rootfs to a working file. Apple VZ's daemon holds the disk
	// image open after shutdown, preventing reuse on the next boot.
	workingRootfs := cfg.RootfsPath + ".active"
	if err := copyFile(cfg.RootfsPath, workingRootfs); err != nil {
		return nil, fmt.Errorf("copying rootfs for boot: %w", err)
	}

	// Disk (rootfs)
	diskAttachment, err := vz.NewDiskImageStorageDeviceAttachment(workingRootfs, false)
	if err != nil {
		_ = os.Remove(workingRootfs)
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

	// Serial console — write to a file so the operator can inspect
	// VM boot output via `agentcage logs --service vm`.
	consoleLogPath := filepath.Join(cfg.ShareDir, "vm-console.log")
	consoleLog, err := os.OpenFile(consoleLogPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return nil, fmt.Errorf("creating VM console log: %w", err)
	}
	serialAttachment, err := vz.NewFileHandleSerialPortAttachment(os.Stdin, consoleLog)
	if err != nil {
		_ = consoleLog.Close()
		return nil, fmt.Errorf("creating serial attachment: %w", err)
	}
	serialPort, err := vz.NewVirtioConsoleDeviceSerialPortConfiguration(serialAttachment)
	if err != nil {
		_ = consoleLog.Close()
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

	// Nested virtualization: enables /dev/kvm inside the guest so
	// Firecracker can run cage microVMs. Requires M3+ and macOS 15+.
	if vz.IsNestedVirtualizationSupported() {
		platform, err := vz.NewGenericPlatformConfiguration()
		if err != nil {
			return nil, fmt.Errorf("creating platform config: %w", err)
		}
		if err := platform.SetNestedVirtualizationEnabled(true); err != nil {
			return nil, fmt.Errorf("enabling nested virtualization: %w", err)
		}
		vmCfg.SetPlatformVirtualMachineConfiguration(platform)
		fmt.Println("     Nested virtualization enabled (/dev/kvm available in VM)")
	} else {
		return nil, fmt.Errorf("nested virtualization not supported on this hardware (requires M3+ chip with macOS 15+)")
	}

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

	v := &LinuxVM{
		machine:        machine,
		consoleLogPath: consoleLogPath,
	}

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

// waitForGRPC scans the NAT subnet for the VM's gRPC port.
// Apple Virtualization.framework assigns IPs from 192.168.64.0/24 via DHCP.
// Other VMs (Docker, UTM) may consume lower addresses, so we scan the full
// range in parallel rather than guessing a handful of candidates.
func (v *LinuxVM) waitForGRPC(ctx context.Context) error {
	port := fmt.Sprintf("%d", grpcPort)
	start := time.Now()

	for {
		if ip, ok := v.scanSubnet(ctx, port); ok {
			v.mu.Lock()
			v.ip = ip
			v.mu.Unlock()
			elapsed := int(time.Since(start).Seconds())
			fmt.Printf("\r     Waiting for VM... ready at %s (%ds)          \n", ip, elapsed)
			return nil
		}

		if v.machine.State() == vz.VirtualMachineStateStopped {
			fmt.Printf("\r     Waiting for VM... stopped                      \n")
			return fmt.Errorf("VM exited unexpectedly (check: agentcage logs --service vm)")
		}

		if data, err := os.ReadFile(v.consoleLogPath); err == nil {
			if bytes.Contains(data, []byte("Kernel panic")) {
				fmt.Printf("\r     Waiting for VM... crashed                      \n")
				_ = v.machine.Stop()
				return fmt.Errorf("VM kernel panic (check: agentcage logs --service vm)")
			}
		}

		elapsed := int(time.Since(start).Seconds())
		min := elapsed / 60
		sec := elapsed % 60
		fmt.Printf("\r     Waiting for VM... %dm%02ds", min, sec)

		select {
		case <-ctx.Done():
			fmt.Println()
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
}

// scanSubnet tries every host in 192.168.64.2-254 concurrently.
// Returns the first IP that accepts a TCP connection on the given port.
func (v *LinuxVM) scanSubnet(_ context.Context, port string) (string, bool) {
	type result struct{ ip string }
	found := make(chan result, 1)

	var wg sync.WaitGroup
	for i := 2; i <= 254; i++ {
		ip := fmt.Sprintf("192.168.64.%d", i)
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, port), 1*time.Second)
			if err != nil {
				return
			}
			_ = conn.Close()
			select {
			case found <- result{ip: ip}:
			default:
			}
		}(ip)
	}

	// Close found channel once all goroutines finish so the select below
	// can detect "nobody found anything" via channel close.
	go func() {
		wg.Wait()
		close(found)
	}()

	if r, ok := <-found; ok {
		return r.ip, true
	}
	return "", false
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

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()

	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}

	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		_ = os.Remove(dst)
		return err
	}
	return out.Close()
}
