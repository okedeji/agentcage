package fleet

type CageResources struct {
	VCPUs    int32
	MemoryMB int32
}

func CalculateSlots(host Host, res CageResources) int32 {
	if res.VCPUs <= 0 || res.MemoryMB <= 0 {
		return 0
	}
	cpuSlots := host.VCPUsTotal / res.VCPUs
	memSlots := host.MemoryMBTotal / res.MemoryMB
	if cpuSlots < memSlots {
		return cpuSlots
	}
	return memSlots
}

// CalculateMixedSlots estimates total cage slots for a typical workload mix.
// The 60/40 split reflects observed production ratios where validators
// outnumber discovery and escalation cages roughly 3:2.
func CalculateMixedSlots(host Host, validatorRes, discoveryRes CageResources) int32 {
	validatorSlots := CalculateSlots(host, validatorRes)
	discoverySlots := CalculateSlots(host, discoveryRes)
	return int32(float64(validatorSlots)*0.6 + float64(discoverySlots)*0.4)
}
