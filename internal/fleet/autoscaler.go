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
	Terminate(ctx context.Context, hostID string) error
	CheckReady(ctx context.Context, hostID string) (bool, error)
}

type AutoscalerConfig struct {
	PollInterval            time.Duration
	MinBuffer               int32
	MaxBuffer               int32
	DefaultCageResources    CageResources
	ProvisioningTimeout     time.Duration
	EmergencyProvisionCount int32
}

// AlertNotifier dispatches fleet operational alerts. Satisfied by
// alert.Dispatcher without fleet importing the alert package.
type AlertNotifier interface {
	Notify(ctx context.Context, source, category, description, cageID, assessmentID string, priority int, details map[string]any)
}

type Autoscaler struct {
	pool        *PoolManager
	demand      *DemandLedger
	provisioner HostProvisioner
	alerter     AlertNotifier
	config      AutoscalerConfig
	logger      logr.Logger
}

func NewAutoscaler(pool *PoolManager, demand *DemandLedger, provisioner HostProvisioner, alerter AlertNotifier, config AutoscalerConfig, logger logr.Logger) *Autoscaler {
	return &Autoscaler{
		pool:        pool,
		demand:      demand,
		provisioner: provisioner,
		alerter:     alerter,
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
	a.promoteReadyHosts(ctx)
	a.cleanupDrainedHosts(ctx)

	warmHosts := a.pool.GetHostsByPool(PoolWarm)
	provisioningHosts := a.pool.GetHostsByPool(PoolProvisioning)
	warmCount := int32(len(warmHosts))
	pendingCount := int32(len(provisioningHosts))
	effectiveWarm := warmCount + pendingCount

	// Calculate how many warm hosts demand requires
	demandHosts := a.hostsForDemand()
	target := max(a.config.MinBuffer, demandHosts)

	// Scale up if below target
	if effectiveWarm < target {
		gap := target - effectiveWarm
		a.logger.Info("warm pool below target, provisioning", "warm", warmCount, "provisioning", pendingCount, "target", target, "gap", gap)
		a.provisionHosts(ctx, gap)
		return
	}

	// Emergency: if fleet utilization is above 90%, provision regardless
	// of warm count to prevent cage creation failures.
	status := a.pool.GetFleetStatus()
	if status.CapacityUtilizationRatio > 0.9 && status.TotalHosts > 0 {
		count := a.config.EmergencyProvisionCount
		if count <= 0 {
			count = 2
		}
		a.logger.Info("fleet utilization critical, emergency provisioning", "utilization", status.CapacityUtilizationRatio, "count", count)
		if a.alerter != nil {
			a.alerter.Notify(ctx, "behavioral", "fleet_capacity_critical", fmt.Sprintf("fleet utilization at %.0f%%, emergency provisioning %d hosts", status.CapacityUtilizationRatio*100, count), "", "", 3, map[string]any{"utilization": status.CapacityUtilizationRatio})
		}
		a.provisionHosts(ctx, count)
		return
	}

	// Scale down: drain unpinned warm hosts that exceed target
	if warmCount > target {
		excess := warmCount - target
		a.logger.Info("warm pool above target, draining excess", "warm", warmCount, "target", target, "draining", excess)

		sort.Slice(warmHosts, func(i, j int) bool {
			return warmHosts[i].UpdatedAt.Before(warmHosts[j].UpdatedAt)
		})

		var drained int32
		for _, h := range warmHosts {
			if drained >= excess {
				break
			}
			if ctx.Err() != nil {
				return
			}
			if h.Pinned {
				continue
			}
			if err := a.provisioner.Drain(ctx, h.ID); err != nil {
				a.logger.Error(err, "draining excess warm host", "host_id", h.ID)
				continue
			}
			if err := a.pool.MoveHost(h.ID, PoolDraining); err != nil {
				a.logger.Error(err, "moving drained host to draining pool", "host_id", h.ID)
				continue
			}
			a.logger.V(1).Info("host drained from warm pool", "host_id", h.ID)
			drained++
		}
	}
}

func (a *Autoscaler) hostsForDemand() int32 {
	demand := a.demand.CurrentDemand()
	if demand <= 0 {
		return 0
	}
	slotsPerHost := a.averageSlotsPerHost()
	if slotsPerHost <= 0 {
		return 0
	}
	return (demand + slotsPerHost - 1) / slotsPerHost
}

// averageSlotsPerHost returns the average cage slots across all active and
// warm hosts in the fleet. Falls back to a calculation from a typical host
// spec if the fleet is empty (e.g., before any hosts are provisioned).
func (a *Autoscaler) averageSlotsPerHost() int32 {
	status := a.pool.GetFleetStatus()
	var totalSlots, hostCount int32
	for _, ps := range status.Pools {
		if ps.Pool == PoolActive || ps.Pool == PoolWarm {
			totalSlots += ps.CageSlotsTotal
			hostCount += ps.HostCount
		}
	}
	if hostCount > 0 {
		return totalSlots / hostCount
	}
	fallback := Host{VCPUsTotal: 64, MemoryMBTotal: 131072}
	return CalculateSlots(fallback, a.config.DefaultCageResources)
}

func (a *Autoscaler) provisionHosts(ctx context.Context, count int32) {
	for range count {
		if ctx.Err() != nil {
			return
		}
		host, err := a.provisioner.Provision(ctx)
		if err != nil {
			a.logger.Error(err, "provisioning host")
			if a.alerter != nil {
				a.alerter.Notify(ctx, "behavioral", "fleet_provision_failed", fmt.Sprintf("failed to provision host: %v", err), "", "", 3, map[string]any{"error": err.Error()})
			}
			continue
		}
		a.pool.AddHost(*host)
		a.logger.V(1).Info("host provisioning started", "host_id", host.ID)
	}
}

const defaultProvisioningTimeout = 15 * time.Minute

func (a *Autoscaler) promoteReadyHosts(ctx context.Context) {
	provisioning := a.pool.GetHostsByPool(PoolProvisioning)
	now := time.Now()
	for _, h := range provisioning {
		if ctx.Err() != nil {
			return
		}
		timeout := a.config.ProvisioningTimeout
		if timeout <= 0 {
			timeout = defaultProvisioningTimeout
		}
		if now.Sub(h.UpdatedAt) > timeout {
			a.logger.Error(fmt.Errorf("host %s stuck in provisioning for %s", h.ID, now.Sub(h.UpdatedAt)),
				"terminating stuck provisioning host")
			if a.alerter != nil {
				a.alerter.Notify(ctx, "behavioral", "fleet_host_stuck", fmt.Sprintf("host %s stuck in provisioning for %s, terminating", h.ID, now.Sub(h.UpdatedAt)), "", "", 3, map[string]any{"host_id": h.ID})
			}
			if err := a.provisioner.Terminate(ctx, h.ID); err != nil {
				a.logger.Error(err, "terminating stuck host", "host_id", h.ID)
			}
			_ = a.pool.RemoveHost(h.ID)
			continue
		}
		ready, err := a.provisioner.CheckReady(ctx, h.ID)
		if err != nil {
			a.logger.V(1).Info("checking host readiness", "host_id", h.ID, "error", err)
			continue
		}
		if ready {
			if err := a.pool.MoveHost(h.ID, PoolWarm); err != nil {
				a.logger.Error(err, "promoting host to warm pool", "host_id", h.ID)
				continue
			}
			a.logger.Info("host ready, promoted to warm pool", "host_id", h.ID)
		}
	}
}

func (a *Autoscaler) cleanupDrainedHosts(ctx context.Context) {
	draining := a.pool.GetHostsByPool(PoolDraining)
	for _, h := range draining {
		if ctx.Err() != nil {
			return
		}
		if h.CageSlotsUsed > 0 {
			continue
		}
		if err := a.provisioner.Terminate(ctx, h.ID); err != nil {
			a.logger.Error(err, "terminating drained host", "host_id", h.ID)
			continue
		}
		if err := a.pool.RemoveHost(h.ID); err != nil {
			a.logger.Error(err, "removing terminated host from pool", "host_id", h.ID)
			continue
		}
		a.logger.Info("drained host terminated and removed", "host_id", h.ID)
	}
}

func (a *Autoscaler) OnNewAssessment(assessmentID string, surfaceSize int) {
	peakCages := estimatePeakCages(surfaceSize)

	slotsPerHost := a.averageSlotsPerHost()
	if slotsPerHost <= 0 {
		a.logger.Error(fmt.Errorf("slots per host is zero"), "cannot estimate hosts needed")
		return
	}

	hostsNeeded := (int32(peakCages) + slotsPerHost - 1) / slotsPerHost

	status := a.pool.GetFleetStatus()
	var availableSlots int32
	for _, ps := range status.Pools {
		if ps.Pool == PoolActive || ps.Pool == PoolWarm || ps.Pool == PoolProvisioning {
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
