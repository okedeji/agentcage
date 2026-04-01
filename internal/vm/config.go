package vm

// Config holds the VM boot configuration.
type Config struct {
	VCPUs      int
	MemoryMB   int
	KernelPath string
	RootfsPath string
	ShareDir   string // host directory to mount via VirtioFS
	ShareTag   string // VirtioFS mount tag
}

// DefaultConfig returns a VM configuration with sensible defaults.
func DefaultConfig(agentcageHome string) Config {
	return Config{
		VCPUs:      vmCPUs,
		MemoryMB:   vmMemoryMB,
		KernelPath: KernelPath(),
		RootfsPath: RootfsPath(),
		ShareDir:   agentcageHome,
		ShareTag:   "agentcage",
	}
}
