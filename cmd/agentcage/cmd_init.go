package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"strings"
	"path/filepath"

	"github.com/go-logr/logr"

	"github.com/okedeji/agentcage/internal/assessment"
	"github.com/okedeji/agentcage/internal/cage"
	"github.com/okedeji/agentcage/internal/config"
	"github.com/okedeji/agentcage/internal/embedded"
	"github.com/okedeji/agentcage/internal/enforcement"
	"github.com/okedeji/agentcage/internal/findings"
	"github.com/okedeji/agentcage/internal/fleet"
	"github.com/okedeji/agentcage/internal/identity"
	agentgrpc "github.com/okedeji/agentcage/internal/grpc"
	"github.com/okedeji/agentcage/internal/intervention"
	proxylog "github.com/okedeji/agentcage/internal/log"
)

// Keeps darwin builds happy; cmdInit is dispatched from platform_linux.go.
var _ = cmdInit

func cmdInit(args []string) {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	configFile := fs.String("config", "", "path to config YAML override file")
	logFormat := fs.String("log-format", "json", "log output format (json or text)")
	_ = fs.Parse(args)

	if err := runInit(*configFile, *logFormat); err != nil {
		fmt.Fprintf(os.Stderr, "agentcage init: %v\n", err)
		os.Exit(1)
	}
}

func runInit(configFile, logFormat string) error {
	defaultPath := config.DefaultPath()
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

	spireSocket := resolveSpireSocket(cfg)
	trustDomain := resolveTrustDomain(cfg)

	otelShutdown, err := setupTelemetry(ctx, cfg, log)
	if err != nil {
		return err
	}
	defer otelShutdown()

	opaEngine, err := buildPolicyEngine(cfg)
	if err != nil {
		return err
	}

	// Identity and secrets must resolve before database and NATS because
	// external service URLs (with embedded credentials) live in Vault.
	svidIssuer, secretFetcher, secretReader, identityCleanup, err := connectIdentityAndSecrets(ctx, cfg, embeddedMgr, spireSocket, log)
	if err != nil {
		return err
	}

	if valErr := validateRequiredSecrets(ctx, secretReader, cfg); valErr != nil {
		identityCleanup()
		return valErr
	}

	natsURL, err := resolveNATSURL(ctx, cfg, secretReader)
	if err != nil {
		identityCleanup()
		return err
	}

	db, err := connectDatabase(ctx, cfg, secretReader, log)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()

	findingsBus, findingStore, findingsCoordinator, err := connectFindingsBus(ctx, cfg, natsURL, spireSocket, trustDomain, db, log)
	if err != nil {
		return err
	}
	defer findingsBus.Close()

	temporalClient, temporalNamespace, err := connectTemporal(ctx, cfg, secretReader, spireSocket, trustDomain, log)
	if err != nil {
		return err
	}
	defer temporalClient.Close()

	iStore, notifier, alertDispatcher := setupNotifications(db, cfg, log)
	scopeValidator := enforcement.NewScopeValidator(cfg)
	cageValidator := buildCageValidator(cfg, opaEngine, scopeValidator, alertDispatcher)

	fleetSetup, err := setupFleet(ctx, cfg, secretReader, alertDispatcher, log)
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

	cageSvc := cage.NewService(temporalClient, cageValidator, db, cfg.LLM.Endpoint, natsURL, cfg.InterventionHoldControlAddr(), cage.TimeoutsFromConfig(cfg.Timeouts), cfg.InterventionTimeout())
	fleetSvc := fleet.NewService(fleetSetup.pool, fleetSetup.demand, fleetSetup.provisioner, log.WithValues("component", "fleet"))
	assessmentSvc := assessment.NewService(temporalClient, db, fleetSetup.autoscaler, cfg.Assessment.MaxIterations)

	iQueue := intervention.NewQueue(iStore, notifier, log.WithValues("component", "intervention-queue"))
	iSvc := intervention.NewService(iQueue, temporalClient, log.WithValues("component", "intervention-service"))

	llmClient, tokenMeter, err := buildLLMClient(ctx, cfg, secretReader, alertDispatcher, log)
	if err != nil {
		return err
	}

	proofLib, err := loadProofLibrary(cfg, log)
	if err != nil {
		return err
	}
	iSvc.SetProofReloader(proofLib)

	cageRuntime, err := setupCageRuntime(ctx, cfg, db, log)
	if err != nil {
		return err
	}

	holdControlAddr := cfg.InterventionHoldControlAddr()
	payloadHoldHandler := cage.NewPayloadHoldHandler(cage.PayloadHoldConfig{
		Enqueuer:        &interventionQueueAdapter{q: iQueue},
		InterventionTTL: cfg.InterventionTimeout(),
		ControlPort:     portFromAddr(holdControlAddr),
		Log:             log,
	})
	iSvc.SetPayloadHoldResolver(payloadHoldHandler)

	agentHoldListener := cage.NewAgentHoldListener(cage.AgentHoldListenerConfig{
		Enqueuer:        &interventionQueueAdapter{q: iQueue},
		InterventionTTL: cfg.InterventionTimeout(),
		Log:             log,
	})
	iSvc.SetAgentHoldResolver(agentHoldListener)

	cageLogDir := filepath.Join(embedded.DataDir(), "cage-logs")
	fileSink, err := cage.NewFileSink(cageLogDir)
	if err != nil {
		return fmt.Errorf("creating cage log sink: %w", err)
	}
	defer fileSink.Close()

	var logSink cage.LogSink = fileSink
	if nb, ok := findingsBus.(*findings.NATSBus); ok {
		natsSink := cage.NewNATSLogSink(nb.Conn())
		logSink = cage.NewMultiSink(fileSink, natsSink)
	}
	logCollector := cage.NewVsockCollector(log.WithValues("component", "vsock-collector"), logSink)

	cageActivityImpl := cage.NewActivityImpl(cage.ActivityImplConfig{
		Provisioner:       cageRuntime.provisioner,
		Rootfs:            cageRuntime.rootfs,
		BundleStoreDir:    filepath.Join(embedded.DataDir(), "bundles"),
		Network:           cageRuntime.network,
		Validator:         scopeValidator,
		AlertHandler:      alertHandler,
		AlertNotifier:     alertDispatcher,
		FalcoReader:       cageRuntime.falcoReader,
		FleetPool:         fleet.NewCagePoolAdapter(fleetSetup.pool),
		AuditStore:        cageRuntime.auditStore,
		Identity:          svidIssuer,
		Secrets:           secretFetcher,
		InterventionQueue: &interventionQueueAdapter{q: iQueue},
		PayloadHolds:      payloadHoldHandler,
		AgentHolds:        agentHoldListener,
		LogCollector:      logCollector,
		LogDir:            cageLogDir,
		Log:               log,
	})

	assessmentActivityImpl := assessment.NewActivityImpl(assessment.ActivityImplConfig{
		Cages:         cageSvc,
		Findings:      findingStore,
		Bus:           findingsBus,
		Coordinator:   findingsCoordinator,
		Fleet:         fleetSetup.autoscaler,
		Assessments:   assessmentSvc,
		Tokens:        tokenMeter,
		LLMClient:     llmClient,
		Proofs:        proofLib,
		Interventions: iSvc,
		Log:           log,
	})

	grpcServer, reloadableCert, err := buildGRPCServer(ctx, cfg, spireSocket, trustDomain, agentgrpc.Services{
		Cages:         cageSvc,
		Assessments:   assessmentSvc,
		Interventions: iSvc,
		Fleet:         fleetSvc,
		Findings:      findingStore,
		CageLogDir:    cageLogDir,
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
	timeoutEnforcer := intervention.NewTimeoutEnforcer(iQueue, temporalClient, notifier, pollInterval, cfg.InterventionWarningThreshold(), enforcerLog)
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

	grpcAddr := cfg.GRPCListenAddr()
	lis, _, err := startGRPCListener(grpcAddr, cfg, log)
	if err != nil {
		return err
	}
	serveGRPC(grpcServer, lis, cancel, log)

	if err := startHoldControlServer(holdControlAddr, payloadHoldHandler, cancel, log); err != nil {
		shutdownSequence(cancel, deps, nil, log)
		return fmt.Errorf("starting payload hold control server: %w", err)
	}

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

func validateRequiredSecrets(ctx context.Context, reader identity.SecretReader, cfg *config.Config) error {
	type required struct {
		path      string
		label     string
		condition bool
	}
	checks := []required{
		{identity.PathLLMKey, "orchestrator llm-api-key", cfg.LLM.Endpoint != ""},
		{identity.PathNATSURL, "orchestrator nats-url", cfg.Infrastructure.IsExternalNATS()},
		{identity.PathPostgresURL, "orchestrator postgres-url", cfg.Infrastructure.IsExternalPostgres()},
		{identity.PathJudgeKey, "orchestrator judge-api-key", cfg.JudgeEndpoint() != ""},
	}
	if cfg.Infrastructure.IsExternalTemporal() {
		checks = append(checks, required{identity.PathTemporalKey, "orchestrator temporal-api-key", true})
	}

	var needed []string
	for _, c := range checks {
		if c.condition {
			needed = append(needed, c.label)
		}
	}

	if reader == nil {
		if len(needed) > 0 {
			return fmt.Errorf("vault not available but required secrets are configured: %v\nimport secrets with: agentcage vault import --from-file secrets.env", needed)
		}
		return nil
	}

	var missing []string
	for _, c := range checks {
		if !c.condition {
			continue
		}
		val, err := identity.ReadSecretValue(ctx, reader, c.path)
		if err != nil || val == "" {
			missing = append(missing, c.label)
		}
	}

	if len(missing) == 0 {
		return nil
	}

	var b strings.Builder
	b.WriteString("required secrets missing from Vault:\n")
	for _, m := range missing {
		fmt.Fprintf(&b, "  %s\n", m)
	}
	b.WriteString("\nImport from file:  agentcage vault import --from-file secrets.env\n")
	b.WriteString("Add individually:  agentcage vault put <scope> <key> <value>\n")
	return errors.New(b.String())
}
