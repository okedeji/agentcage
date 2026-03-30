package fleet

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/go-logr/logr"
)

type HostProvisioner interface {
	Provision(ctx context.Context) (*Host, error)
	Drain(ctx context.Context, hostID string) error
}

type AutoscalerConfig struct {
	PollInterval         time.Duration
	MinBuffer            int32
	MaxBuffer            int32
	DefaultCageResources CageResources
}

type Autoscaler struct {
	pool        *PoolManager
	demand      *DemandLedger
	provisioner HostProvisioner
	config      AutoscalerConfig
	logger      logr.Logger
}

func NewAutoscaler(pool *PoolManager, demand *DemandLedger, provisioner HostProvisioner, config AutoscalerConfig, logger logr.Logger) *Autoscaler {
	return &Autoscaler{
		pool:        pool,
		demand:      demand,
		provisioner: provisioner,
		config:      config,
		logger:      logger,
	}
}

func (a *Autoscaler) Run(ctx context.Context) error {
	ticker := time.NewTicker(a.config.PollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			a.reconcile(ctx)
		}
	}
}

func (a *Autoscaler) reconcile(ctx context.Context) {
	warmHosts := a.pool.GetHostsByPool(PoolWarm)
	warmCount := int32(len(warmHosts))

	if warmCount < a.config.MinBuffer {
		gap := a.config.MinBuffer - warmCount
		a.logger.Info("warm pool below minimum, provisioning", "warm", warmCount, "min_buffer", a.config.MinBuffer, "provisioning", gap)
		for range gap {
			if ctx.Err() != nil {
				return
			}
			host, err := a.provisioner.Provision(ctx)
			if err != nil {
				a.logger.Error(err, "provisioning host for warm pool")
				continue
			}
			host.Pool = PoolWarm
			a.pool.AddHost(*host)
			a.logger.V(1).Info("host provisioned into warm pool", "host_id", host.ID)
		}
		return
	}

	if warmCount > a.config.MaxBuffer && a.demand.CurrentDemand() == 0 {
		excess := warmCount - a.config.MaxBuffer
		a.logger.Info("warm pool above maximum with no demand, draining", "warm", warmCount, "max_buffer", a.config.MaxBuffer, "draining", excess)

		sort.Slice(warmHosts, func(i, j int) bool {
			return warmHosts[i].UpdatedAt.Before(warmHosts[j].UpdatedAt)
		})

		for i := int32(0); i < excess; i++ {
			if ctx.Err() != nil {
				return
			}
			h := warmHosts[i]
			if err := a.provisioner.Drain(ctx, h.ID); err != nil {
				a.logger.Error(err, "draining excess warm host", "host_id", h.ID)
				continue
			}
			if err := a.pool.MoveHost(h.ID, PoolDraining); err != nil {
				a.logger.Error(err, "moving drained host to draining pool", "host_id", h.ID)
				continue
			}
			a.logger.V(1).Info("host drained from warm pool", "host_id", h.ID)
		}
	}
}

func (a *Autoscaler) OnNewAssessment(assessmentID string, surfaceSize int) {
	peakCages := estimatePeakCages(surfaceSize)

	typicalHost := Host{
		VCPUsTotal:    64,
		MemoryMBTotal: 131072,
	}
	slotsPerHost := CalculateSlots(typicalHost, a.config.DefaultCageResources)
	if slotsPerHost <= 0 {
		a.logger.Error(fmt.Errorf("slots per host is zero"), "cannot estimate hosts needed", "cage_resources", a.config.DefaultCageResources)
		return
	}

	hostsNeeded := (int32(peakCages) + slotsPerHost - 1) / slotsPerHost

	status := a.pool.GetFleetStatus()
	var availableSlots int32
	for _, ps := range status.Pools {
		if ps.Pool == PoolActive || ps.Pool == PoolWarm {
			availableSlots += ps.CageSlotsTotal - ps.CageSlotsUsed
		}
	}
	availableHosts := availableSlots / slotsPerHost

	gap := hostsNeeded - availableHosts
	if gap > 0 {
		a.logger.Info("pre-provisioning for assessment", "assessment_id", assessmentID, "surface_size", surfaceSize, "peak_cages", peakCages, "hosts_needed", hostsNeeded, "gap", gap)
		for range gap {
			host, err := a.provisioner.Provision(context.Background())
			if err != nil {
				a.logger.Error(err, "pre-provisioning host for assessment", "assessment_id", assessmentID)
				continue
			}
			host.Pool = PoolWarm
			a.pool.AddHost(*host)
		}
	}

	a.demand.AddDemand(assessmentID, int32(peakCages))
}

func (a *Autoscaler) OnAssessmentComplete(assessmentID string) {
	a.demand.RemoveDemand(assessmentID)
}

func estimatePeakCages(surfaceSize int) int {
	switch {
	case surfaceSize < 50:
		return 150
	case surfaceSize < 200:
		return 500
	default:
		return 1500
	}
}
