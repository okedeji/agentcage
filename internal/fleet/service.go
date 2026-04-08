package fleet

import (
	"context"
	"fmt"

	"github.com/go-logr/logr"
)

type Service struct {
	pool        *PoolManager
	demand      *DemandLedger
	provisioner HostProvisioner
	logger      logr.Logger
}

func NewService(pool *PoolManager, demand *DemandLedger, provisioner HostProvisioner, logger logr.Logger) *Service {
	return &Service{
		pool:        pool,
		demand:      demand,
		provisioner: provisioner,
		logger:      logger,
	}
}

func (s *Service) GetFleetStatus(_ context.Context) (FleetStatus, error) {
	return s.pool.GetFleetStatus(), nil
}

var ErrHostPinned = fmt.Errorf("host is pinned (likely control plane); use force to drain")

func (s *Service) DrainHost(ctx context.Context, hostID string, reason string, force bool) error {
	host, err := s.pool.GetHost(hostID)
	if err != nil {
		return fmt.Errorf("draining host %s: %w", hostID, err)
	}
	if host.Pinned && !force {
		return fmt.Errorf("host %s: %w", hostID, ErrHostPinned)
	}
	if s.provisioner != nil {
		if err := s.provisioner.Drain(ctx, hostID); err != nil {
			return fmt.Errorf("draining host %s via provisioner: %w", hostID, err)
		}
	}
	if err := s.pool.MoveHost(hostID, PoolDraining); err != nil {
		return fmt.Errorf("draining host %s: moving to draining pool: %w", hostID, err)
	}
	if host.Pinned {
		s.logger.Info("pinned host drained (forced)", "host_id", hostID, "reason", reason)
	} else {
		s.logger.Info("host drained", "host_id", hostID, "reason", reason)
	}
	return nil
}

func (s *Service) GetCapacity(_ context.Context) ([]PoolStatus, int32, error) {
	statuses := s.pool.GetPoolStatus()
	var available int32
	for _, ps := range statuses {
		if ps.Pool == PoolActive || ps.Pool == PoolWarm {
			available += ps.CageSlotsTotal - ps.CageSlotsUsed
		}
	}
	return statuses, available, nil
}
