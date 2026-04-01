package vm

import (
	"os"
	"path/filepath"
	"runtime"
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

func homeDir() string {
	if d := os.Getenv("AGENTCAGE_HOME"); d != "" {
		return d
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ".agentcage"
	}
	return filepath.Join(home, ".agentcage")
}
