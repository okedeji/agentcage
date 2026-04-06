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
// Uses a default ratio of 60% validators, 25% discovery, 15% escalation.
// These defaults will be replaced by observed ratios once enough
// assessment history is available.
func CalculateMixedSlots(host Host, validatorRes, discoveryRes, escalationRes CageResources) int32 {
	validatorSlots := CalculateSlots(host, validatorRes)
	discoverySlots := CalculateSlots(host, discoveryRes)
	escalationSlots := CalculateSlots(host, escalationRes)
	return int32(float64(validatorSlots)*0.60 + float64(discoverySlots)*0.25 + float64(escalationSlots)*0.15)
}
