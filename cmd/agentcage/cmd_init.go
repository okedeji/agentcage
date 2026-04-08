package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/go-logr/logr"

	"github.com/okedeji/agentcage/internal/assessment"
	"github.com/okedeji/agentcage/internal/cage"
	"github.com/okedeji/agentcage/internal/config"
	"github.com/okedeji/agentcage/internal/embedded"
	"github.com/okedeji/agentcage/internal/enforcement"
	"github.com/okedeji/agentcage/internal/fleet"
	agentgrpc "github.com/okedeji/agentcage/internal/grpc"
	"github.com/okedeji/agentcage/internal/intervention"
	proxylog "github.com/okedeji/agentcage/internal/log"
)

// Keeps darwin builds happy; cmdInit is dispatched from platform_linux.go.
var _ = cmdInit

func cmdInit(args []string) {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	configFile := fs.String("config", "", "path to config YAML override file")
	grpcAddr := fs.String("grpc-addr", "127.0.0.1:9090", "gRPC server listen address. Loopback only by default; pass 0.0.0.0:9090 to expose on all interfaces, but only with auth/TLS configured.")
	logFormat := fs.String("log-format", "json", "log output format (json or text)")
	_ = fs.Parse(args)

	if err := runInit(*configFile, *grpcAddr, *logFormat); err != nil {
		fmt.Fprintf(os.Stderr, "agentcage init: %v\n", err)
		os.Exit(1)
	}
}

func runInit(configFile, grpcAddr, logFormat string) error {
	defaultPath, err := config.DefaultPath()
	if err != nil {
		return fmt.Errorf("resolving default config path: %w", err)
	}
	created, err := config.WriteDefaults(defaultPath)
	if err != nil {
		return fmt.Errorf("writing default config: %w", err)
	}
	if created {
		fmt.Printf("Config written to %s\n", defaultPath)
	}
	cfg := config.Defaults()
	if resolved := config.Resolve(configFile); resolved != "" {
		override, loadErr := config.Load(resolved)
		if loadErr != nil {
			return fmt.Errorf("loading config %s: %w", resolved, loadErr)
		}
		cfg = config.Merge(cfg, override)
	}

	var log logr.Logger
	if logFormat == "text" {
		log, err = proxylog.NewDev()
	} else {
		log, err = proxylog.New()
	}
	if err != nil {
		return fmt.Errorf("creating logger: %w", err)
	}
	log = log.WithValues("component", "agentcage")

	fmt.Printf("Initializing agentcage v%s...\n\n", version)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Falco rules go to disk before the daemon starts. Otherwise it
	// misses the first batch of cage events.
	alertHandler, err := writeFalcoRules(cfg, log)
	if err != nil {
		return err
	}

	embeddedMgr := embedded.NewManager(cfg, log)
	fmt.Println("Downloading dependencies...")
	if err := embeddedMgr.Download(ctx); err != nil {
		return fmt.Errorf("downloading dependencies: %w", err)
	}
	fmt.Println("\nStarting local services...")
	if err := embeddedMgr.Start(ctx); err != nil {
		return fmt.Errorf("starting local services: %w", err)
	}

	db, err := connectDatabase(ctx, cfg, log)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()

	findingsBus, findingStore, findingsCoordinator, err := connectFindingsBus(cfg, db, log)
	if err != nil {
		return err
	}
	defer findingsBus.Close()

	otelShutdown, err := setupTelemetry(ctx, cfg, log)
	if err != nil {
		return err
	}
	defer otelShutdown()

	opaEngine, err := buildPolicyEngine(cfg)
	if err != nil {
		return err
	}

	spireSocket := resolveSpireSocket(cfg)

	temporalClient, temporalNamespace, err := connectTemporal(ctx, cfg, spireSocket, log)
	if err != nil {
		return err
	}
	defer temporalClient.Close()

	iStore, notifier, alertDispatcher := setupNotifications(db, cfg, log)
	scopeValidator := enforcement.NewScopeValidator(cfg)
	cageValidator := buildCageValidator(cfg, opaEngine, scopeValidator, alertDispatcher)

	fleetSetup, err := setupFleet(cfg, alertDispatcher, log)
	if err != nil {
		return err
	}
	autoscalerLog := log.WithValues("component", "autoscaler")
	fmt.Println("Starting fleet autoscaler...")
	go func() {
		// If the autoscaler dies, fleet scaling stops. Cancel everything
		// so the operator notices instead of running degraded.
		if err := fleetSetup.autoscaler.Run(ctx); err != nil {
			autoscalerLog.Error(err, "autoscaler stopped, triggering orchestrator shutdown")
		} else {
			autoscalerLog.Info("autoscaler stopped")
		}
		if ctx.Err() == nil {
			cancel()
		}
	}()

	cageSvc := cage.NewService(temporalClient, cageValidator, db)
	fleetSvc := fleet.NewService(fleetSetup.pool, fleetSetup.demand, fleetSetup.provisioner, log.WithValues("component", "fleet"))
	assessmentSvc := assessment.NewService(temporalClient, db, fleetSetup.autoscaler)

	iQueue := intervention.NewQueue(iStore, notifier, log.WithValues("component", "intervention-queue"))
	iSvc := intervention.NewService(iQueue, temporalClient, log.WithValues("component", "intervention-service"))

	llmClient, err := buildLLMClient(cfg, alertDispatcher, log)
	if err != nil {
		return err
	}

	proofLib, err := loadProofLibrary(cfg, log)
	if err != nil {
		return err
	}
	// Operator-edited proofs need to land before the workflow retries.
	iSvc.SetProofReloader(proofLib)

	cageRuntime, err := setupCageRuntime(ctx, cfg, db, log)
	if err != nil {
		return err
	}

	svidIssuer, secretFetcher, identityCleanup, err := connectIdentityAndSecrets(ctx, cfg, embeddedMgr, spireSocket, log)
	if err != nil {
		return err
	}

	cageActivityImpl := cage.NewActivityImpl(cage.ActivityImplConfig{
		Provisioner:   cageRuntime.provisioner,
		Rootfs:        cageRuntime.rootfs,
		Network:       cageRuntime.network,
		Validator:     scopeValidator,
		AlertHandler:  alertHandler,
		AlertNotifier: alertDispatcher,
		FalcoReader:   cageRuntime.falcoReader,
		FleetPool:     fleet.NewCagePoolAdapter(fleetSetup.pool),
		AuditStore:    cageRuntime.auditStore,
		Identity:      svidIssuer,
		Secrets:       secretFetcher,
		Log:           log,
	})

	assessmentActivityImpl := assessment.NewActivityImpl(assessment.ActivityImplConfig{
		Cages:         cageSvc,
		Findings:      findingStore,
		Bus:           findingsBus,
		Coordinator:   findingsCoordinator,
		Fleet:         fleetSetup.autoscaler,
		LLMClient:     llmClient,
		Proofs:        proofLib,
		Interventions: iSvc,
		Log:           log,
	})

	grpcServer, reloadableCert, err := buildGRPCServer(ctx, cfg, spireSocket, agentgrpc.Services{
		Cages:         cageSvc,
		Assessments:   assessmentSvc,
		Interventions: iSvc,
		Fleet:         fleetSvc,
		Cancel:        cancel,
		Version:       version,
	}, log)
	if err != nil {
		return err
	}

	cageWorker, assessmentWorker := buildTemporalWorkers(
		ctx, cancel, temporalClient,
		fleetSetup.pool.TotalCageSlots(),
		cageActivityImpl, assessmentActivityImpl, log,
	)

	// Workers must be polling before gRPC accepts traffic. The readiness
	// probe inside startTemporalWorkers closes the race.
	if err := startTemporalWorkers(ctx, temporalClient, temporalNamespace, cageWorker, assessmentWorker, log); err != nil {
		return err
	}

	enforcerLog := log.WithValues("component", "timeout-enforcer")
	pollInterval := cfg.InterventionPollInterval()
	timeoutEnforcer := intervention.NewTimeoutEnforcer(iQueue, temporalClient, pollInterval, enforcerLog)
	enforcerLog.Info("timeout enforcer started", "interval", pollInterval)
	go func() {
		// If the enforcer dies, timed-out interventions stop firing.
		// Cancel everything so the operator notices.
		if err := timeoutEnforcer.Run(ctx); err != nil {
			enforcerLog.Error(err, "stopped, triggering orchestrator shutdown")
		} else {
			enforcerLog.Info("stopped")
		}
		if ctx.Err() == nil {
			cancel()
		}
	}()

	deps := shutdownDeps{
		grpcServer:       grpcServer,
		cageWorker:       cageWorker,
		assessmentWorker: assessmentWorker,
		identityCleanup:  identityCleanup,
		alertDispatcher:  alertDispatcher,
		embeddedMgr:      embeddedMgr,
	}

	lis, _, err := startGRPCListener(grpcAddr, cfg, log)
	if err != nil {
		return err
	}
	serveGRPC(grpcServer, lis, cancel, log)

	if err := waitForGRPCReady(ctx, cfg, grpcAddr); err != nil {
		shutdownSequence(cancel, deps, nil, log)
		return fmt.Errorf("waiting for gRPC server: %w", err)
	}

	pidFile := filepath.Join(embedded.RunDir(), "agentcage.pid")
	if err := writePIDFile(pidFile); err != nil {
		// `agentcage stop` and systemd both read this file. If we can't
		// write it, we'd rather refuse to start than start unstoppable.
		shutdownSequence(cancel, deps, nil, log)
		return fmt.Errorf("pid file: %w", err)
	}
	defer func() {
		if rmErr := os.Remove(pidFile); rmErr != nil && !errors.Is(rmErr, fs.ErrNotExist) {
			log.Error(rmErr, "removing pid file on shutdown", "path", pidFile)
		}
	}()

	// lis.Addr() resolves the real port for ephemeral binds (`:0`).
	fmt.Printf("\nagentcage ready.\n")
	fmt.Printf("  gRPC:     %s\n", lis.Addr().String())
	fmt.Printf("  Temporal: %s\n", resolveTemporalAddr(cfg))
	fmt.Printf("  Data:     %s\n\n", embedded.DataDir())
	fmt.Println("Press Ctrl+C to stop.")

	sigCh := waitForShutdown(ctx, cfg, reloadableCert, log)

	shutdownSequence(cancel, deps, sigCh, log)

	return nil
}
