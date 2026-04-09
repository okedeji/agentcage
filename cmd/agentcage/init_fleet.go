package main

import (
	"fmt"
	"os"
	"time"

	"github.com/go-logr/logr"

	"github.com/okedeji/agentcage/internal/alert"
	"github.com/okedeji/agentcage/internal/config"
	"github.com/okedeji/agentcage/internal/fleet"
)

type fleetSetup struct {
	pool         *fleet.PoolManager
	demand       *fleet.DemandLedger
	provisioner  fleet.HostProvisioner
	autoscaler   *fleet.Autoscaler
	validatorRes fleet.CageResources
}

// Autoscaler is constructed here but started in runInit so its
// cancel-on-death hookup shares context with the rest of shutdown.
func setupFleet(cfg *config.Config, alertDispatcher *alert.Dispatcher, log logr.Logger) (*fleetSetup, error) {
	pool := fleet.NewPoolManager()
	demand := fleet.NewDemandLedger()

	// config.Defaults() always populates these three keys.
	cageRes := func(name string) fleet.CageResources {
		c := cfg.Cages[name]
		return fleet.CageResources{VCPUs: c.MaxVCPUs, MemoryMB: c.MaxMemoryMB}
	}
	validatorRes := cageRes("validator")
	discoveryRes := cageRes("discovery")
	escalationRes := cageRes("escalation")

	fmt.Println("Initializing fleet pool...")
	if err := fleet.InitPool(pool, cfg.Fleet.Hosts, validatorRes, discoveryRes, escalationRes); err != nil {
		return nil, fmt.Errorf("initializing fleet pool: %w", err)
	}
	status := pool.GetFleetStatus()
	totalSlots := int32(0)
	for _, p := range status.Pools {
		totalSlots += p.CageSlotsTotal
	}
	log.Info("fleet pool initialized", "hosts", status.TotalHosts, "total_slots", totalSlots)

	provisioner := buildHostProvisioner(cfg, log)

	autoscalerCfg := fleet.AutoscalerConfig{
		PollInterval:         30 * time.Second,
		MinBuffer:            0,
		MaxBuffer:            1,
		DefaultCageResources: validatorRes,
	}
	if cfg.Fleet.Autoscaler != nil {
		autoscalerCfg.MinBuffer = cfg.Fleet.Autoscaler.MinWarmHosts
		autoscalerCfg.MaxBuffer = cfg.Fleet.Autoscaler.MaxHosts
		autoscalerCfg.ProvisioningTimeout = cfg.Fleet.Autoscaler.ProvisioningTimeout
		autoscalerCfg.EmergencyProvisionCount = cfg.Fleet.Autoscaler.EmergencyProvisionCount
	}
	autoscaler := fleet.NewAutoscaler(pool, demand, provisioner, alertDispatcher, autoscalerCfg, log.WithValues("component", "autoscaler"))

	return &fleetSetup{
		pool:         pool,
		demand:       demand,
		provisioner:  provisioner,
		autoscaler:   autoscaler,
		validatorRes: validatorRes,
	}, nil
}

func buildHostProvisioner(cfg *config.Config, log logr.Logger) fleet.HostProvisioner {
	pc := cfg.Fleet.Provisioner
	if pc != nil && pc.WebhookURL != "" {
		var apiKey string
		if pc.APIKeyEnvVar != "" {
			apiKey = os.Getenv(pc.APIKeyEnvVar)
		}
		log.Info("fleet provisioner: webhook", "url", pc.WebhookURL)
		return fleet.NewWebhookProvisioner(pc.WebhookURL, apiKey, pc.Timeout, log)
	}
	log.Info("fleet provisioner: local (single machine, no scaling)")
	return fleet.NewLocalHostProvisioner(log)
}

