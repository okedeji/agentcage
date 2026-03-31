package embedded

import (
	"context"
	"fmt"

	"github.com/go-logr/logr"

	"github.com/okedeji/agentcage/internal/config"
)

// Manager orchestrates the lifecycle of all embedded infrastructure services.
// Services that the user has configured as external (via config.yaml) are
// skipped entirely.
type Manager struct {
	services []Service
	log      logr.Logger
}

// NewManager creates a Manager with services configured from the unified config.
// External services (where the user provided their own address) are excluded.
func NewManager(cfg *config.Config, log logr.Logger) *Manager {
	m := &Manager{log: log.WithValues("component", "embedded")}

	infra := cfg.Infrastructure

	if !infra.IsExternalPostgres() {
		m.services = append(m.services, NewPostgresService(log))
	}

	if !infra.IsExternalNATS() {
		m.services = append(m.services, NewNATSService(log))
	}

	if !infra.IsExternalTemporal() {
		m.services = append(m.services, NewTemporalService(log))
	}

	if !infra.IsExternalSPIRE() {
		m.services = append(m.services, NewSPIREService(log))
	}

	if !infra.IsExternalVault() {
		m.services = append(m.services, NewVaultService(log))
	}

	if !infra.IsExternalFalco() {
		m.services = append(m.services, NewFalcoService(log))
	}

	m.services = append(m.services, NewFirecrackerDownloader(log))

	return m
}

// Download fetches all required binaries for embedded services.
func (m *Manager) Download(ctx context.Context) error {
	if err := EnsureDirs(); err != nil {
		return fmt.Errorf("creating agentcage directories: %w", err)
	}

	for _, svc := range m.services {
		if svc.IsExternal() {
			continue
		}
		m.log.Info("downloading", "service", svc.Name())
		if err := svc.Download(ctx); err != nil {
			return fmt.Errorf("downloading %s: %w", svc.Name(), err)
		}
		m.log.Info("downloaded", "service", svc.Name())
	}
	return nil
}

// Start launches all embedded services in order. Services that are external
// are skipped. If any service fails to start, previously started services
// are stopped.
func (m *Manager) Start(ctx context.Context) error {
	var started []Service

	for _, svc := range m.services {
		if svc.IsExternal() {
			m.log.Info("skipping external service", "service", svc.Name())
			continue
		}
		m.log.Info("starting", "service", svc.Name())
		if err := svc.Start(ctx); err != nil {
			m.log.Error(err, "failed to start, rolling back", "service", svc.Name())
			m.stopReverse(ctx, started)
			return fmt.Errorf("starting %s: %w", svc.Name(), err)
		}
		m.log.Info("started", "service", svc.Name())
		started = append(started, svc)
	}
	return nil
}

// Stop gracefully shuts down all embedded services in reverse order.
func (m *Manager) Stop(ctx context.Context) error {
	var nonExternal []Service
	for _, svc := range m.services {
		if !svc.IsExternal() {
			nonExternal = append(nonExternal, svc)
		}
	}
	return m.stopReverse(ctx, nonExternal)
}

// Health checks all running embedded services.
func (m *Manager) Health(ctx context.Context) map[string]error {
	results := make(map[string]error)
	for _, svc := range m.services {
		if svc.IsExternal() {
			continue
		}
		results[svc.Name()] = svc.Health(ctx)
	}
	return results
}

func (m *Manager) stopReverse(ctx context.Context, services []Service) error {
	var errs []error
	for i := len(services) - 1; i >= 0; i-- {
		svc := services[i]
		m.log.Info("stopping", "service", svc.Name())
		if err := svc.Stop(ctx); err != nil {
			m.log.Error(err, "error stopping service", "service", svc.Name())
			errs = append(errs, fmt.Errorf("stopping %s: %w", svc.Name(), err))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("errors during shutdown: %v", errs)
	}
	return nil
}
