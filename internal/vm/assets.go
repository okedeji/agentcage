package vm

import (
	"path/filepath"
	"runtime"

	"github.com/okedeji/agentcage/internal/config"
)

const (
	kernelVersion = "6.1"
	alpineVersion = "3.19"
	vmMemoryMB    = 4096
	vmCPUs        = 4
	grpcPort      = 9090
)

// Dir returns the directory where VM assets (kernel, rootfs, linux binary) are stored.
func Dir() string {
	return filepath.Join(homeDir(), "vm")
}

func KernelPath() string {
	return filepath.Join(Dir(), "vmlinux-"+kernelVersion+"-"+runtime.GOARCH)
}


func RootfsPath() string {
	return filepath.Join(Dir(), "rootfs-"+alpineVersion+"-"+runtime.GOARCH+".img")
}

func LinuxBinaryPath() string {
	return filepath.Join(Dir(), "agentcage-linux-"+runtime.GOARCH)
}

func CageRootfsPath() string {
	return filepath.Join(Dir(), "cage-rootfs.img")
}

func homeDir() string {
	return config.HomeDir()
}
