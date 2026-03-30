package fleet

import (
	"context"
	"fmt"

	"github.com/go-logr/logr"
)

type Server struct {
	pool   *PoolManager
	demand *DemandLedger
	logger logr.Logger
}

func NewServer(pool *PoolManager, demand *DemandLedger, logger logr.Logger) *Server {
	return &Server{
		pool:   pool,
		demand: demand,
		logger: logger,
	}
}

func (s *Server) GetFleetStatus(_ context.Context) (FleetStatus, error) {
	return s.pool.GetFleetStatus(), nil
}

func (s *Server) DrainHost(_ context.Context, hostID string, reason string) error {
	if _, err := s.pool.GetHost(hostID); err != nil {
		return fmt.Errorf("draining host %s: %w", hostID, err)
	}
	if err := s.pool.MoveHost(hostID, PoolDraining); err != nil {
		return fmt.Errorf("draining host %s: moving to draining pool: %w", hostID, err)
	}
	s.logger.Info("host drained", "host_id", hostID, "reason", reason)
	return nil
}

func (s *Server) GetCapacity(_ context.Context) ([]PoolStatus, int32, error) {
	statuses := s.pool.GetPoolStatus()
	var available int32
	for _, ps := range statuses {
		if ps.Pool == PoolActive || ps.Pool == PoolWarm {
			available += ps.CageSlotsTotal - ps.CageSlotsUsed
		}
	}
	return statuses, available, nil
}
