package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
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

	"github.com/okedeji/agentcage/internal/alert"
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

	// Write Falco rules before starting services so the Falco daemon
	// can load them at startup.
	fmt.Println("Generating Falco rules...")
	falcoRules, tripwires := enforcement.GenerateFalcoRules(cfg.Monitoring)
	falcoHandler := enforcement.NewFalcoHandlerFromGenerated(tripwires)
	alertHandler := enforcement.NewFalcoAlertAdapter(falcoHandler)

	falcoRulesDir := filepath.Join(embedded.RunDir(), "falco", "rules.d")
	if err := enforcement.WriteFalcoRules(falcoRules, falcoRulesDir); err != nil {
		return fmt.Errorf("writing Falco rules: %w", err)
	}
	log.Info("Falco rules written", "dir", falcoRulesDir)

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

	// --- Temporal client ---

	spireSocket := filepath.Join(embedded.RunDir(), "spire", "agent.sock")
	if cfg.Infrastructure.IsExternalSPIRE() && cfg.Infrastructure.SPIRE.AgentSocket != "" {
		spireSocket = cfg.Infrastructure.SPIRE.AgentSocket
	}

	temporalAddr := "localhost:17233"
	if cfg.Infrastructure.IsExternalTemporal() {
		temporalAddr = cfg.Infrastructure.Temporal.Address
	}

	fmt.Println("Connecting to Temporal...")
	temporalOpts := client.Options{
		HostPort: temporalAddr,
	}
	if tc := cfg.Infrastructure.Temporal; tc != nil {
		if tc.Namespace != "" {
			temporalOpts.Namespace = tc.Namespace
		}
		if tc.TLS != nil {
			switch {
			case tc.TLS.Internal:
				internalTLS, spireErr := agentgrpc.SPIREClientTLS(ctx, "unix://"+spireSocket)
				if spireErr != nil {
					return fmt.Errorf("configuring internal mTLS for Temporal: %w", spireErr)
				}
				temporalOpts.ConnectionOptions = client.ConnectionOptions{
					TLS: internalTLS,
				}
				log.Info("Temporal mTLS enabled via internal identity provider")
			case tc.TLS.CertFile != "":
				cert, tlsErr := tls.LoadX509KeyPair(tc.TLS.CertFile, tc.TLS.KeyFile)
				if tlsErr != nil {
					return fmt.Errorf("loading Temporal TLS cert: %w", tlsErr)
				}
				tlsCfg := &tls.Config{Certificates: []tls.Certificate{cert}}
				if tc.TLS.CAFile != "" {
					caCert, caErr := os.ReadFile(tc.TLS.CAFile)
					if caErr != nil {
						return fmt.Errorf("reading Temporal CA file: %w", caErr)
					}
					pool := x509.NewCertPool()
					pool.AppendCertsFromPEM(caCert)
					tlsCfg.RootCAs = pool
				}
				temporalOpts.ConnectionOptions = client.ConnectionOptions{
					TLS: tlsCfg,
				}
				log.Info("Temporal mTLS enabled", "cert", tc.TLS.CertFile)
			}
		}
		if tc.APIKeyEnvVar != "" {
			apiKey := os.Getenv(tc.APIKeyEnvVar)
			if apiKey == "" {
				return fmt.Errorf("temporal API key env var %s is not set", tc.APIKeyEnvVar)
			}
			temporalOpts.Credentials = client.NewAPIKeyStaticCredentials(apiKey)
			log.Info("Temporal API key auth enabled")
		}
	}
	temporalClient, err := client.Dial(temporalOpts)
	if err != nil {
		return fmt.Errorf("connecting to Temporal at %s: %w", temporalAddr, err)
	}
	defer temporalClient.Close()

	// --- Notifications and alerts ---

	fmt.Println("Setting up notifications...")

	iStore := intervention.NewPGStore(db)

	var notifiers []intervention.Notifier
	notifiers = append(notifiers, intervention.NewLogNotifier(log))
	for _, wh := range cfg.Notifications.Webhooks {
		if wh.URL == "" {
			continue
		}
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
	alertDispatcher := alert.NewDispatcher(notifier, log)

	cageValidator := func(c cage.Config) error {
		if validErr := enforcement.ValidateCageConfig(c, cfg); validErr != nil {
			alertDispatcher.Dispatch(context.Background(), alert.Event{
				Source:       alert.SourcePolicy,
				Category:     alert.CategoryCageConfigViolation,
				Priority:     intervention.PriorityCritical,
				AssessmentID: c.AssessmentID,
				Description:  validErr.Error(),
				Details:      map[string]any{"layer": "go"},
			})
			return validErr
		}
		scopeDecision, scopeErr := opaEngine.EvaluateScope(context.Background(), c.Scope, cfg.Scope.Deny)
		if scopeErr != nil {
			alertDispatcher.Dispatch(context.Background(), alert.Event{
				Source:       alert.SourcePolicy,
				Category:     alert.CategoryScopeViolation,
				Priority:     intervention.PriorityCritical,
				AssessmentID: c.AssessmentID,
				Description:  fmt.Sprintf("OPA scope engine error: %v", scopeErr),
				Details:      map[string]any{"layer": "opa", "error": scopeErr.Error()},
			})
			return fmt.Errorf("evaluating scope policy: %w", scopeErr)
		}
		if !scopeDecision.Allowed {
			alertDispatcher.Dispatch(context.Background(), alert.Event{
				Source:       alert.SourcePolicy,
				Category:     alert.CategoryScopeViolation,
				Priority:     intervention.PriorityCritical,
				AssessmentID: c.AssessmentID,
				Description:  scopeDecision.Reason,
				Details:      map[string]any{"violations": scopeDecision.Violations, "layer": "opa"},
			})
			return fmt.Errorf("scope rejected: %s", scopeDecision.Reason)
		}
		decision, evalErr := opaEngine.EvaluateCageConfig(context.Background(), c)
		if evalErr != nil {
			alertDispatcher.Dispatch(context.Background(), alert.Event{
				Source:       alert.SourcePolicy,
				Category:     alert.CategoryCageConfigViolation,
				Priority:     intervention.PriorityCritical,
				AssessmentID: c.AssessmentID,
				Description:  fmt.Sprintf("OPA config engine error: %v", evalErr),
				Details:      map[string]any{"layer": "opa", "error": evalErr.Error()},
			})
			return fmt.Errorf("evaluating cage config policy: %w", evalErr)
		}
		if !decision.Allowed {
			alertDispatcher.Dispatch(context.Background(), alert.Event{
				Source:       alert.SourcePolicy,
				Category:     alert.CategoryCageConfigViolation,
				Priority:     intervention.PriorityCritical,
				AssessmentID: c.AssessmentID,
				Description:  decision.Reason,
				Details:      map[string]any{"violations": decision.Violations, "layer": "opa"},
			})
			return fmt.Errorf("cage config rejected: %s", decision.Reason)
		}
		return nil
	}
	// --- Fleet ---

	poolManager := fleet.NewPoolManager()
	demandLedger := fleet.NewDemandLedger()

	validatorRes := fleet.CageResources{VCPUs: 1, MemoryMB: 1024}
	if vc, ok := cfg.Cages["validator"]; ok {
		validatorRes = fleet.CageResources{VCPUs: vc.MaxVCPUs, MemoryMB: vc.MaxMemoryMB}
	}
	discoveryRes := fleet.CageResources{VCPUs: 2, MemoryMB: 4096}
	if dc, ok := cfg.Cages["discovery"]; ok {
		discoveryRes = fleet.CageResources{VCPUs: dc.MaxVCPUs, MemoryMB: dc.MaxMemoryMB}
	}
	escalationRes := fleet.CageResources{VCPUs: 2, MemoryMB: 4096}
	if ec, ok := cfg.Cages["escalation"]; ok {
		escalationRes = fleet.CageResources{VCPUs: ec.MaxVCPUs, MemoryMB: ec.MaxMemoryMB}
	}

	fmt.Println("Initializing fleet pool...")
	if err := fleet.InitPool(poolManager, cfg.Fleet.Hosts, validatorRes, discoveryRes, escalationRes); err != nil {
		return fmt.Errorf("initializing fleet pool: %w", err)
	}
	fleetStatus := poolManager.GetFleetStatus()
	log.Info("fleet pool initialized", "hosts", fleetStatus.TotalHosts, "total_slots", func() int32 {
		var s int32
		for _, p := range fleetStatus.Pools {
			s += p.CageSlotsTotal
		}
		return s
	}())

	var hostProvisioner fleet.HostProvisioner
	if pc := cfg.Fleet.Provisioner; pc != nil && pc.WebhookURL != "" {
		var apiKey string
		if pc.APIKeyEnvVar != "" {
			apiKey = os.Getenv(pc.APIKeyEnvVar)
		}
		hostProvisioner = fleet.NewWebhookProvisioner(pc.WebhookURL, apiKey, pc.Timeout, log)
		log.Info("fleet provisioner: webhook", "url", pc.WebhookURL)
	} else {
		hostProvisioner = fleet.NewLocalHostProvisioner(log)
		log.Info("fleet provisioner: local (single machine, no scaling)")
	}
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
	autoscaler := fleet.NewAutoscaler(poolManager, demandLedger, hostProvisioner, alertDispatcher, autoscalerCfg, log.WithValues("component", "autoscaler"))

	fmt.Println("Starting fleet autoscaler...")
	go func() {
		if err := autoscaler.Run(ctx); err != nil {
			log.Error(err, "autoscaler stopped")
		}
	}()

	// --- Domain services ---

	cageSvc := cage.NewService(temporalClient, cageValidator, db)
	assessmentSvc := assessment.NewService(temporalClient, db, autoscaler)
	fleetSvc := fleet.NewService(poolManager, demandLedger, hostProvisioner, log.WithValues("component", "fleet"))

	iQueue := intervention.NewQueue(iStore, notifier, log.WithValues("component", "intervention-queue"))
	iSvc := intervention.NewService(iQueue, temporalClient, log.WithValues("component", "intervention-service"))

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

	var falcoReader *cage.FalcoAlertReader
	falcoSocket := filepath.Join(embedded.RunDir(), "falco", "falco.sock")
	if cfg.Infrastructure.Falco != nil && cfg.Infrastructure.Falco.Socket != "" {
		falcoSocket = cfg.Infrastructure.Falco.Socket
	}
	if _, socketErr := os.Stat(falcoSocket); socketErr == nil {
		falcoReader = cage.NewFalcoAlertReader(falcoSocket, log)
		log.Info("Falco alert reader configured", "socket", falcoSocket)
	}

	cageActivityImpl := cage.NewActivityImpl(cage.ActivityImplConfig{
		Provisioner:   cageProvisioner,
		Rootfs:        rootfsBuilder,
		Network:       networkEnforcer,
		AlertHandler:  alertHandler,
		AlertNotifier: alertDispatcher,
		FalcoReader:   falcoReader,
		FleetPool:     &fleetPoolAdapter{pool: poolManager},
		AuditStore:    auditStore,
		Identity:      svidIssuer,
		Secrets:       secretFetcher,
		Log:           log,
	})

	// --- Assessment activity implementation ---

	assessmentActivityImpl := assessment.NewActivityImpl(assessment.ActivityImplConfig{
		Cages:       cageSvc,
		Findings:    findingStore,
		Bus:         findingsBus,
		Coordinator: findingsCoordinator,
		Fleet:       autoscaler,
		LLMClient:   llmClient,
		Playbooks:   proofLib,
		Log:         log,
	})

	// --- gRPC server ---

	var grpcOpts []grpc.ServerOption
	switch {
	case cfg.GRPC.UseInternalTLS():
		tlsCfg, tlsErr := agentgrpc.SPIREServerTLS(ctx, "unix://"+spireSocket)
		if tlsErr != nil {
			return fmt.Errorf("configuring internal mTLS for gRPC: %w", tlsErr)
		}
		grpcOpts = append(grpcOpts, grpc.Creds(credentials.NewTLS(tlsCfg)))
		log.Info("gRPC mTLS enabled via internal identity provider")
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
		Cages:         cageSvc,
		Assessments:   assessmentSvc,
		Interventions: iSvc,
		Fleet:         fleetSvc,
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
	alertDispatcher.Close()

	if err := mgr.Stop(context.Background()); err != nil {
		log.Error(err, "error stopping embedded services")
	}

	_ = os.Remove(pidFile)
	fmt.Println("agentcage stopped.")
	return nil
}

// fleetPoolAdapter bridges fleet.PoolManager to the cage.FleetPool interface,
// avoiding a direct import from cage → fleet (which would create a cycle).
type fleetPoolAdapter struct {
	pool *fleet.PoolManager
}

func (a *fleetPoolAdapter) GetAvailableHost() (*cage.FleetHost, error) {
	h, err := a.pool.GetAvailableHost()
	if err != nil {
		return nil, err
	}
	return &cage.FleetHost{ID: h.ID, Pool: int(h.Pool)}, nil
}

func (a *fleetPoolAdapter) AllocateCageSlot(hostID string) error {
	return a.pool.AllocateCageSlot(hostID)
}

func (a *fleetPoolAdapter) ReleaseCageSlot(hostID string) error {
	return a.pool.ReleaseCageSlot(hostID)
}

func (a *fleetPoolAdapter) MoveHost(hostID string, toPool int) error {
	return a.pool.MoveHost(hostID, fleet.HostPool(toPool))
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
