package fleet

import "time"

type HostPool int

const (
	PoolActive HostPool = iota + 1
	PoolWarm
	PoolProvisioning
	PoolDraining
)

func (p HostPool) String() string {
	switch p {
	case PoolActive:
		return "active"
	case PoolWarm:
		return "warm"
	case PoolProvisioning:
		return "provisioning"
	case PoolDraining:
		return "draining"
	default:
		return "unknown"
	}
}

type HostState int

const (
	HostInitializing HostState = iota + 1
	HostReady
	HostBusy
	HostDraining
	HostOffline
)

func (s HostState) String() string {
	switch s {
	case HostInitializing:
		return "initializing"
	case HostReady:
		return "ready"
	case HostBusy:
		return "busy"
	case HostDraining:
		return "draining"
	case HostOffline:
		return "offline"
	default:
		return "unknown"
	}
}

type Host struct {
	ID             string
	Pool           HostPool
	State          HostState
	CageSlotsTotal int32
	CageSlotsUsed  int32
	VCPUsTotal     int32
	VCPUsUsed      int32
	MemoryMBTotal  int32
	MemoryMBUsed   int32
	UpdatedAt      time.Time
}

type PoolStatus struct {
	Pool           HostPool
	HostCount      int32
	CageSlotsTotal int32
	CageSlotsUsed  int32
}

type FleetStatus struct {
	TotalHosts               int32
	Pools                    []PoolStatus
	CapacityUtilizationRatio float64
}
