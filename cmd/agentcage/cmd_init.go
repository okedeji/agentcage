package main

import (
	"context"
	"database/sql"
	"flag"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/go-logr/logr"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/worker"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	_ "github.com/lib/pq"

	"github.com/okedeji/agentcage/migrations"

	"github.com/okedeji/agentcage/internal/audit"
	"github.com/okedeji/agentcage/internal/assessment"
	"github.com/okedeji/agentcage/internal/cage"
	"github.com/okedeji/agentcage/internal/config"
	agentgrpc "github.com/okedeji/agentcage/internal/grpc"
	"github.com/okedeji/agentcage/internal/embedded"
	"github.com/okedeji/agentcage/internal/enforcement"
	"github.com/okedeji/agentcage/internal/findings"
	"github.com/okedeji/agentcage/internal/fleet"
	"github.com/okedeji/agentcage/internal/gateway"
	"github.com/okedeji/agentcage/internal/identity"
	"github.com/okedeji/agentcage/internal/intervention"
	proxylog "github.com/okedeji/agentcage/internal/log"
	"github.com/okedeji/agentcage/internal/metrics"
)

var _ = cmdInit

func cmdInit(args []string) {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	configFile := fs.String("config", "", "path to config YAML override file")
	grpcAddr := fs.String("grpc-addr", ":9090", "gRPC server listen address")
	logFormat := fs.String("log-format", "json", "log output format (json or text)")
	_ = fs.Parse(args)

	if err := runInit(*configFile, *grpcAddr, *logFormat); err != nil {
		fmt.Fprintf(os.Stderr, "agentcage init: %v\n", err)
		os.Exit(1)
	}
}

func runInit(configFile, grpcAddr, logFormat string) error {
	// --- Configuration ---

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
		override, err := config.Load(resolved)
		if err != nil {
			return fmt.Errorf("loading config %s: %w", resolved, err)
		}
		cfg = config.Merge(cfg, override)
	}

	// --- Logger ---

	var (
		log    logr.Logger
		logErr error
	)
	if logFormat == "text" {
		log, logErr = proxylog.NewDev()
	} else {
		log, logErr = proxylog.New()
	}
	if logErr != nil {
		return fmt.Errorf("creating logger: %w", logErr)
	}
	log = log.WithValues("component", "agentcage")

	// --- Embedded infrastructure ---

	mgr := embedded.NewManager(cfg, log)

	fmt.Printf("Initializing agentcage v%s...\n\n", version)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	fmt.Println("Downloading dependencies...")
	if err := mgr.Download(ctx); err != nil {
		return fmt.Errorf("downloading dependencies: %w", err)
	}

	fmt.Println("\nStarting local services...")
	if err := mgr.Start(ctx); err != nil {
		return fmt.Errorf("starting local services: %w", err)
	}

	// --- Database ---

	var dbURL string
	if cfg.Infrastructure.IsExternalPostgres() {
		dbURL = cfg.Infrastructure.Postgres.URL
	} else {
		var urlErr error
		dbURL, urlErr = embedded.PostgresURL()
		if urlErr != nil {
			return fmt.Errorf("resolving embedded Postgres URL: %w", urlErr)
		}
	}
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		return fmt.Errorf("opening database: %w", err)
	}
	defer func() { _ = db.Close() }()

	fmt.Println("Connecting to database...")
	if err := db.PingContext(ctx); err != nil {
		return fmt.Errorf("connecting to database: %w", err)
	}
	log.Info("database connected", "url", redactDBURL(dbURL))

	fmt.Println("Running database migrations...")
	applied, err := migrations.Up(ctx, db)
	if err != nil {
		return fmt.Errorf("running migrations: %w", err)
	}
	if len(applied) > 0 {
		fmt.Printf("  %d migration(s) applied.\n", len(applied))
	}
	for _, name := range applied {
		log.Info("migration applied", "name", name)
	}

	// --- NATS findings bus ---

	var natsURL string
	if cfg.Infrastructure.IsExternalNATS() {
		natsURL = cfg.Infrastructure.NATS.URL
	} else {
		natsURL = embedded.NATSURL()
	}

	fmt.Println("Connecting to NATS findings bus...")
	findingsBus, err := findings.NewNATSBus(natsURL)
	if err != nil {
		return fmt.Errorf("connecting to NATS at %s: %w", natsURL, err)
	}
	defer findingsBus.Close()

	findingStore := findings.NewPGFindingStore(db)
	bloom := findings.NewBloomFilter(100000, 7)
	var sanitizeLimits *findings.SanitizeLimits
	if cfg.Assessment.MaxScreenshotSize > 0 {
		sanitizeLimits = &findings.SanitizeLimits{MaxScreenshotSize: cfg.Assessment.MaxScreenshotSize}
	}
	findingsCoordinator := findings.NewCoordinator(findingStore, bloom, sanitizeLimits, log.WithValues("component", "findings-coordinator"))

	log.Info("findings bus connected", "url", natsURL)

	// --- Metrics ---

	fmt.Println("Initializing telemetry...")
	if cfg.Infrastructure.IsExternalOTel() {
		metricOpts := []otlpmetricgrpc.Option{
			otlpmetricgrpc.WithEndpointURL(cfg.Infrastructure.OTel.Endpoint),
		}
		traceOpts := []otlptracegrpc.Option{
			otlptracegrpc.WithEndpointURL(cfg.Infrastructure.OTel.Endpoint),
		}
		if cfg.Infrastructure.OTel.Insecure {
			metricOpts = append(metricOpts, otlpmetricgrpc.WithInsecure())
			traceOpts = append(traceOpts, otlptracegrpc.WithInsecure())
		}
		metricExp, metricErr := otlpmetricgrpc.New(ctx, metricOpts...)
		if metricErr != nil {
			return fmt.Errorf("creating OTLP metric exporter: %w", metricErr)
		}
		traceExp, traceErr := otlptracegrpc.New(ctx, traceOpts...)
		if traceErr != nil {
			return fmt.Errorf("creating OTLP trace exporter: %w", traceErr)
		}
		otelShutdown, setupErr := metrics.Setup(ctx, metricExp, traceExp)
		if setupErr != nil {
			return fmt.Errorf("setting up OTel providers: %w", setupErr)
		}
		defer func() {
			shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer shutdownCancel()
			if err := otelShutdown(shutdownCtx); err != nil {
				log.Error(err, "flushing OTel providers")
			}
		}()
		log.Info("OTel telemetry enabled", "endpoint", cfg.Infrastructure.OTel.Endpoint)
	}

	if err := metrics.Init(); err != nil {
		return fmt.Errorf("initializing metrics: %w", err)
	}

	// --- OPA policy engine (generated from config) ---

	fmt.Println("Configuring policy engine...")
	modules := enforcement.GenerateRegoModules(cfg)
	opaEngine, err := enforcement.NewOPAEngineFromModules(modules)
	if err != nil {
		return fmt.Errorf("creating OPA engine: %w", err)
	}

	// --- Falco rules (generated from config) ---

	fmt.Println("Generating Falco rules...")
	_, tripwires := enforcement.GenerateFalcoRules(cfg.Monitoring)
	falcoHandler := enforcement.NewFalcoHandlerFromGenerated(tripwires)
	alertHandler := enforcement.NewFalcoAlertAdapter(falcoHandler)

	// --- Temporal client ---

	temporalAddr := "localhost:17233"
	if cfg.Infrastructure.IsExternalTemporal() {
		temporalAddr = cfg.Infrastructure.Temporal.Address
	}

	fmt.Println("Connecting to Temporal...")
	temporalClient, err := client.Dial(client.Options{
		HostPort: temporalAddr,
	})
	if err != nil {
		return fmt.Errorf("connecting to Temporal at %s: %w", temporalAddr, err)
	}
	defer temporalClient.Close()

	// --- Domain servers ---

	fmt.Println("Initializing domain services...")
	cageValidator := func(c cage.Config) error {
		if validErr := enforcement.ValidateCageConfig(c, cfg); validErr != nil {
			return validErr
		}
		scopeDecision, scopeErr := opaEngine.EvaluateScope(context.Background(), c.Scope, cfg.Scope.Deny)
		if scopeErr != nil {
			return fmt.Errorf("evaluating scope policy: %w", scopeErr)
		}
		if !scopeDecision.Allowed {
			return fmt.Errorf("scope rejected: %s", scopeDecision.Reason)
		}
		decision, evalErr := opaEngine.EvaluateCageConfig(context.Background(), c)
		if evalErr != nil {
			return fmt.Errorf("evaluating cage config policy: %w", evalErr)
		}
		if !decision.Allowed {
			return fmt.Errorf("cage config rejected: %s", decision.Reason)
		}
		return nil
	}
	cageServer := cage.NewServer(temporalClient, cageValidator, db)
	assessmentServer := assessment.NewServer(temporalClient, db)

	iStore := intervention.NewPGStore(db)

	var notifiers []intervention.Notifier
	notifiers = append(notifiers, intervention.NewLogNotifier(log))
	if wh := cfg.Notifications.Webhook; wh != nil && wh.URL != "" {
		timeout := wh.Timeout
		if timeout == 0 {
			timeout = 5 * time.Second
		}
		whNotifier := intervention.NewWebhookNotifier([]string{wh.URL}, timeout, log)
		if len(wh.Headers) > 0 {
			whNotifier.SetHeaders(wh.Headers)
		}
		notifiers = append(notifiers, whNotifier)
		log.Info("webhook notifications enabled", "url", wh.URL)
	}
	notifier := intervention.NewMultiNotifier(log, notifiers...)

	iQueue := intervention.NewQueue(iStore, notifier, log.WithValues("component", "intervention-queue"))
	iServer := intervention.NewServer(iQueue, temporalClient, log.WithValues("component", "intervention-server"))

	poolManager := fleet.NewPoolManager()
	demandLedger := fleet.NewDemandLedger()
	fleetServer := fleet.NewServer(poolManager, demandLedger, log.WithValues("component", "fleet"))

	// --- LLM client (for coordinator) ---

	meter := gateway.NewTokenMeter()
	budgetEnforcer := gateway.NewBudgetEnforcer(meter)
	var llmClient *gateway.Client
	if cfg.LLM.Endpoint != "" {
		llmClient = gateway.NewClient(cfg.LLM.Endpoint, cfg.LLM.Timeout, meter, budgetEnforcer)
	}

	// --- Proofs (validation rules) ---

	proofDir := cfg.Assessment.ProofsDir
	if proofDir == "" {
		proofDir = proofsDir()
	}
	fmt.Println("Loading validation rules...")
	if err := seedDefaultProofs(proofDir); err != nil {
		log.Error(err, "seeding default proofs")
	}

	var proofLib *assessment.PlaybookLibrary
	if _, statErr := os.Stat(proofDir); statErr == nil {
		var loadErr error
		proofLib, loadErr = assessment.LoadPlaybooks(proofDir)
		if loadErr != nil {
			log.Error(loadErr, "loading proofs — continuing without proofs")
		} else {
			log.Info("proofs loaded", "dir", proofDir, "count", len(proofLib.List()))
		}
	}

	// --- Cage activity implementation ---

	fmt.Println("Setting up cage provisioner...")
	firecrackerBin := filepath.Join(embedded.BinDir(), "firecracker")
	kernelBin := filepath.Join(embedded.BinDir(), "vmlinux")

	var cageProvisioner cage.VMProvisioner
	if _, kvmErr := os.Stat("/dev/kvm"); kvmErr == nil {
		if _, fcErr := os.Stat(firecrackerBin); fcErr == nil {
			cageProvisioner = cage.NewFirecrackerProvisioner(cage.FirecrackerConfig{
				BinPath:    firecrackerBin,
				KernelPath: kernelBin,
			}, log)
			log.Info("cage provisioner: firecracker", "bin", firecrackerBin, "kernel", kernelBin)
		}
	}
	if cageProvisioner == nil {
		cageProvisioner = cage.NewMockProvisioner()
		log.Info("cage provisioner: Mock/test (no KVM or firecracker binary — cages will not be isolated)")
	}

	networkEnforcer := enforcement.NewNFTablesEnforcer(log)
	auditStore := audit.NewPGStore(db)

	// --- Identity and secrets ---

	fmt.Println("Connecting to identity and secrets services...")
	var svidIssuer identity.SVIDIssuer
	spireSocket := filepath.Join(embedded.RunDir(), "spire", "agent.sock")
	if cfg.Infrastructure.IsExternalSPIRE() && cfg.Infrastructure.SPIRE.AgentSocket != "" {
		spireSocket = cfg.Infrastructure.SPIRE.AgentSocket
	}
	if _, socketErr := os.Stat(spireSocket); socketErr == nil {
		spireClient, spireErr := identity.NewSpireClient(ctx, spireSocket, "agentcage.local")
		if spireErr != nil {
			log.Error(spireErr, "connecting to SPIRE — cages will use dev identities")
		} else {
			svidIssuer = spireClient
			defer func() { _ = spireClient.Close() }()
			log.Info("SPIRE identity issuer connected", "socket", spireSocket)
		}
	}
	if svidIssuer == nil {
		log.Info("SPIRE not available — cages will use dev identities")
	}

	var secretFetcher identity.SecretFetcher
	if cfg.Infrastructure.IsExternalVault() {
		vaultClient, vaultErr := identity.NewVaultClient(
			cfg.Infrastructure.Vault.Address,
			"auth/jwt/login",
			"cage",
		)
		if vaultErr != nil {
			log.Error(vaultErr, "creating Vault client — cages will use dev secrets")
		} else {
			secretFetcher = vaultClient
			log.Info("Vault secret fetcher connected", "addr", cfg.Infrastructure.Vault.Address)
		}
	}
	if secretFetcher == nil {
		log.Info("Vault not configured for production auth — cages will use dev secrets")
	}

	baseRootfs := filepath.Join(embedded.VMDir(), "cage-rootfs.img")
	rootfsWorkDir := filepath.Join(embedded.DataDir(), "rootfs-work")
	if err := os.MkdirAll(rootfsWorkDir, 0755); err != nil {
		return fmt.Errorf("creating rootfs work directory: %w", err)
	}
	rootfsBuilder := cage.NewRootfsBuilder(baseRootfs, rootfsWorkDir, version)

	cageActivityImpl := cage.NewActivityImpl(cage.ActivityImplConfig{
		Provisioner:  cageProvisioner,
		Rootfs:       rootfsBuilder,
		Network:      networkEnforcer,
		AlertHandler: alertHandler,
		AuditStore:   auditStore,
		Identity:     svidIssuer,
		Secrets:      secretFetcher,
		Log:          log,
	})

	// --- Assessment activity implementation ---

	assessmentActivityImpl := assessment.NewActivityImpl(assessment.ActivityImplConfig{
		Cages:       cageServer,
		Findings:    findingStore,
		Bus:         findingsBus,
		Coordinator: findingsCoordinator,
		LLMClient:   llmClient,
		Playbooks:   proofLib,
		Log:         log,
	})

	// --- gRPC server ---

	var grpcOpts []grpc.ServerOption
	switch {
	case cfg.GRPC.UseSPIRETLS():
		tlsCfg, tlsErr := agentgrpc.SPIREServerTLS(ctx, "unix://"+spireSocket)
		if tlsErr != nil {
			return fmt.Errorf("configuring SPIRE mTLS: %w", tlsErr)
		}
		grpcOpts = append(grpcOpts, grpc.Creds(credentials.NewTLS(tlsCfg)))
		log.Info("gRPC mTLS enabled via SPIRE", "socket", spireSocket)
	case cfg.GRPC.UseFileTLS():
		creds, tlsErr := credentials.NewServerTLSFromFile(cfg.GRPC.TLS.CertFile, cfg.GRPC.TLS.KeyFile)
		if tlsErr != nil {
			return fmt.Errorf("loading TLS credentials: %w", tlsErr)
		}
		grpcOpts = append(grpcOpts, grpc.Creds(creds))
		log.Info("gRPC TLS enabled", "cert", cfg.GRPC.TLS.CertFile)
	}
	grpcServer := grpc.NewServer(grpcOpts...)

	agentgrpc.Register(grpcServer, agentgrpc.Services{
		Cages:         cageServer,
		Assessments:   assessmentServer,
		Interventions: iServer,
		Fleet:         fleetServer,
		Cancel:        cancel,
		Version:       version,
	})
	log.Info("gRPC services registered")

	// --- Temporal workers ---

	fmt.Println("Registering Temporal workers...")
	cageWorker := worker.New(temporalClient, cage.TaskQueue, worker.Options{})
	cageWorker.RegisterWorkflow(cage.CageWorkflow)
	cageWorker.RegisterActivity(cageActivityImpl)

	assessmentWorker := worker.New(temporalClient, assessment.TaskQueue, worker.Options{})
	assessmentWorker.RegisterWorkflow(assessment.AssessmentWorkflow)
	assessmentWorker.RegisterActivity(assessmentActivityImpl)

	// --- Timeout enforcer ---

	timeoutEnforcer := intervention.NewTimeoutEnforcer(iQueue, temporalClient, 30*time.Second, log.WithValues("component", "timeout-enforcer"))

	// --- Start gRPC ---

	fmt.Printf("Starting gRPC server on %s...\n", grpcAddr)
	lis, err := net.Listen("tcp", grpcAddr)
	if err != nil {
		return fmt.Errorf("listening on %s: %w", grpcAddr, err)
	}

	go func() {
		if srvErr := grpcServer.Serve(lis); srvErr != nil {
			log.Error(srvErr, "gRPC server failed")
			cancel()
		}
	}()

	// --- Start workers ---

	fmt.Println("Starting Temporal workers...")
	if err := cageWorker.Start(); err != nil {
		return fmt.Errorf("starting cage worker: %w", err)
	}
	if err := assessmentWorker.Start(); err != nil {
		cageWorker.Stop()
		return fmt.Errorf("starting assessment worker: %w", err)
	}
	go func() {
		if tErr := timeoutEnforcer.Run(ctx); tErr != nil {
			log.Error(tErr, "timeout enforcer stopped")
		}
	}()

	pidFile := filepath.Join(embedded.RunDir(), "agentcage.pid")
	if err := os.WriteFile(pidFile, []byte(fmt.Sprintf("%d", os.Getpid())), 0644); err != nil {
		log.Error(err, "writing PID file")
	}

	fmt.Printf("\nagentcage ready.\n")
	fmt.Printf("  gRPC:     %s\n", grpcAddr)
	fmt.Printf("  Temporal: %s\n", temporalAddr)
	fmt.Printf("  Data:     %s\n\n", embedded.DataDir())
	fmt.Println("Press Ctrl+C to stop.")

	// --- Wait for shutdown ---

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-sigCh:
		log.Info("received signal, shutting down", "signal", sig.String())
	case <-ctx.Done():
	}

	fmt.Println("\nShutting down...")

	cancel()
	grpcServer.GracefulStop()
	cageWorker.Stop()
	assessmentWorker.Stop()

	if err := mgr.Stop(context.Background()); err != nil {
		log.Error(err, "error stopping embedded services")
	}

	_ = os.Remove(pidFile)
	fmt.Println("agentcage stopped.")
	return nil
}

func redactDBURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "***"
	}
	if u.User != nil {
		u.User = url.UserPassword(u.User.Username(), "***")
	}
	return u.String()
}
