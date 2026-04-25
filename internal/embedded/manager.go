package embedded

import (
	"context"
	"fmt"
	"time"

	"github.com/go-logr/logr"
	"golang.org/x/sync/errgroup"

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

	if !infra.IsExternalNomad() && infra.Nomad != nil {
		m.services = append(m.services, NewNomadService(log))
	}

	m.services = append(m.services, NewFirecrackerDownloader(log))

	return m
}

// EmbeddedVault returns the embedded VaultService if Vault is running in
// embedded mode, or nil if the operator configured an external Vault.
// Used by cmd_init to wire the orchestrator to the dev token.
func (m *Manager) EmbeddedVault() *VaultService {
	for _, svc := range m.services {
		if v, ok := svc.(*VaultService); ok {
			return v
		}
	}
	return nil
}

// EmbeddedNomad returns the embedded NomadService if Nomad is running
// in embedded mode, or nil otherwise.
func (m *Manager) EmbeddedNomad() *NomadService {
	for _, svc := range m.services {
		if n, ok := svc.(*NomadService); ok {
			return n
		}
	}
	return nil
}

// Download fetches all required binaries for embedded services.
// Downloads run concurrently to reduce first-run startup time.
// Each service's Download skips if the binary already exists.
func (m *Manager) Download(ctx context.Context) error {
	if err := EnsureDirs(); err != nil {
		return fmt.Errorf("creating agentcage directories: %w", err)
	}

	var toDownload []Service
	for _, svc := range m.services {
		if !svc.IsExternal() {
			toDownload = append(toDownload, svc)
		}
	}

	g, gCtx := errgroup.WithContext(ctx)
	for _, svc := range toDownload {
		svc := svc
		g.Go(func() error {
			m.log.Info("downloading", "service", svc.Name())
			if err := svc.Download(gCtx); err != nil {
				return fmt.Errorf("downloading %s: %w", svc.Name(), err)
			}
			m.log.Info("downloaded", "service", svc.Name())
			return nil
		})
	}
	return g.Wait()
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
			_ = m.stopReverse(ctx, started)
			return fmt.Errorf("starting %s: %w", svc.Name(), err)
		}
		// Verify service is healthy before starting the next one
		if err := waitForHealth(ctx, svc, m.log); err != nil {
			m.log.Error(err, "health check failed, rolling back", "service", svc.Name())
			_ = m.stopReverse(ctx, started)
			return fmt.Errorf("health check for %s: %w", svc.Name(), err)
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

func waitForHealth(ctx context.Context, svc Service, log logr.Logger) error {
	deadline := time.Now().Add(15 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		if err := svc.Health(ctx); err == nil {
			return nil
		} else {
			lastErr = err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
	return fmt.Errorf("%s not healthy after 15s: %w", svc.Name(), lastErr)
}
