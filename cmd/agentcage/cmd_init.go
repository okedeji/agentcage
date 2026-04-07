package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"errors"
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
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	enums "go.temporal.io/api/enums/v1"
	taskqueue "go.temporal.io/api/taskqueue/v1"
	"go.temporal.io/api/workflowservice/v1"
	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/worker"
	"go.temporal.io/sdk/workflow"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/reflection"

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
	grpcAddr := fs.String("grpc-addr", "127.0.0.1:9090", "gRPC server listen address (default loopback only; pass 0.0.0.0:9090 to expose on all interfaces — only with auth/TLS configured)")
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
		if cfg.OTelInsecureDefault() {
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
		// Route SDK metrics through OTel so worker internals (task slot
		// availability, workflow task failures, poll latency) flow into
		// the same pipeline as the rest of agentcage.
		MetricsHandler: metrics.NewTemporalMetricsHandler(),
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

	scopeValidator := enforcement.NewScopeValidator(cfg)
	cageValidator := func(c cage.Config) error {
		if validErr := scopeValidator.ValidateCageConfig(context.Background(), c); validErr != nil {
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
	fleetSvc := fleet.NewService(poolManager, demandLedger, hostProvisioner, log.WithValues("component", "fleet"))
	assessmentSvc := assessment.NewService(temporalClient, db, autoscaler)

	iQueue := intervention.NewQueue(iStore, notifier, log.WithValues("component", "intervention-queue"))
	iSvc := intervention.NewService(iQueue, temporalClient, log.WithValues("component", "intervention-service"))

	// --- LLM client (for coordinator) ---

	meter := gateway.NewTokenMeter()
	budgetEnforcer := gateway.NewBudgetEnforcer(meter)
	var llmClient *gateway.Client
	if cfg.LLM.Endpoint == "" {
		if cfg.LLMRequiredDefault() {
			return fmt.Errorf("posture=strict: llm.endpoint is required (the assessment coordinator and discovery cages cannot run without an LLM)")
		}
		log.Info("WARNING: no LLM endpoint configured — assessment coordinator will not be able to plan cages")
	} else {
		var apiKey string
		if cfg.LLM.APIKeyEnv != "" {
			apiKey = os.Getenv(cfg.LLM.APIKeyEnv)
			if apiKey == "" {
				return fmt.Errorf("LLM API key env var %s is not set", cfg.LLM.APIKeyEnv)
			}
		}
		llmClient = gateway.NewClient(cfg.LLM.Endpoint, apiKey, cfg.LLM.Timeout, meter, budgetEnforcer, alertDispatcher)
		log.Info("LLM gateway client configured", "endpoint", cfg.LLM.Endpoint, "auth", apiKey != "")
	}

	// --- Proofs (validation rules) ---

	proofDir := cfg.Assessment.ProofsDir
	if proofDir == "" {
		proofDir = proofsDir()
	}
	fmt.Println("Loading validation rules...")
	switch cfg.Assessment.ProofsMode {
	case config.ProofsModeBYOP:
		// Bring-your-own-proof: never seed defaults. Unfamiliar vuln classes
		// will trigger proof_gap interventions until the operator adds
		// proofs via `agentcage proof add`.
		log.Info("proofs mode: byop (no defaults seeded)")
		if err := os.MkdirAll(proofDir, 0755); err != nil {
			fmt.Fprintf(os.Stderr, "creating proofs directory %s: %v\n", proofDir, err)
			os.Exit(1)
		}
	default:
		log.Info("proofs mode: bundled (seeding any missing defaults)")
		if err := seedDefaultProofs(proofDir); err != nil {
			fmt.Fprintf(os.Stderr, "seeding default proofs: %v\n", err)
			os.Exit(1)
		}
	}

	proofLib, loadErr := assessment.LoadProofs(proofDir)
	if loadErr != nil {
		// Loud failure: a malformed proof YAML must not be silently ignored.
		fmt.Fprintf(os.Stderr, "loading proofs from %s: %v\n", proofDir, loadErr)
		os.Exit(1)
	}
	log.Info("proofs loaded", "dir", proofDir, "count", len(proofLib.List()))

	// Wire the proof library into the intervention service so retry
	// resolutions of proof_gap interventions reload it from disk before
	// signaling the workflow.
	iSvc.SetProofReloader(proofLib)

	// --- Cage activity implementation ---

	fmt.Println("Setting up cage provisioner...")
	binDir := embedded.BinDir()
	log.Info("embedded bin dir", "path", binDir)

	firecrackerBin := cfg.CageRuntime.FirecrackerBin
	if firecrackerBin == "" {
		firecrackerBin = filepath.Join(binDir, "firecracker")
	}
	kernelBin := cfg.CageRuntime.KernelPath
	if kernelBin == "" {
		kernelBin = filepath.Join(binDir, "vmlinux")
	}

	cageProvisioner, isolated, err := cage.BuildProvisioner(ctx, cage.HostRuntimeConfig{
		FirecrackerBin:  firecrackerBin,
		KernelPath:      kernelBin,
		AllowUnisolated: cfg.AllowUnisolatedDefault(),
	}, log)
	if err != nil {
		return fmt.Errorf("setting up cage provisioner: %w", err)
	}

	var networkEnforcer enforcement.NetworkEnforcer
	if isolated {
		networkEnforcer = enforcement.NewNFTablesEnforcer(log)
	} else {
		networkEnforcer = enforcement.NewNoopEnforcer(log)
		log.Info("network enforcement disabled (unisolated cage runtime)")
	}
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
		// Production path: real JWT-SVID from SPIRE, scoped per cage.
		vaultCfg := cfg.Infrastructure.Vault
		authPath := vaultCfg.AuthPath
		if authPath == "" {
			authPath = "auth/jwt/login"
		}
		role := vaultCfg.Role
		if role == "" {
			role = "cage"
		}

		tlsCfg, tlsErr := buildVaultTLSConfig(ctx, cfg, spireSocket)
		if tlsErr != nil {
			return fmt.Errorf("building Vault TLS config: %w", tlsErr)
		}

		jwtSource, jwtErr := identity.NewSpireJWTSource(ctx, spireSocket)
		if jwtErr != nil {
			return fmt.Errorf("opening SPIRE JWT source for Vault auth: %w", jwtErr)
		}

		vaultClient, vaultErr := identity.NewVaultJWTClient(identity.VaultJWTConfig{
			Address:   vaultCfg.Address,
			AuthPath:  authPath,
			Role:      role,
			TLS:       tlsCfg,
			JWTSource: jwtSource,
			Audience:  "vault",
		})
		if vaultErr != nil {
			_ = jwtSource.Close()
			return fmt.Errorf("creating Vault client: %w", vaultErr)
		}

		healthCtx, cancelHealth := context.WithTimeout(ctx, 5*time.Second)
		if err := vaultClient.Health(healthCtx); err != nil {
			cancelHealth()
			_ = jwtSource.Close()
			return fmt.Errorf("vault unreachable at %s: %w", vaultCfg.Address, err)
		}
		cancelHealth()

		secretFetcher = vaultClient
		log.Info("Vault secret fetcher connected (jwt mode)",
			"addr", vaultCfg.Address,
			"auth_path", authPath,
			"role", role,
			"tls", vaultTLSMode(cfg))
	} else if embeddedVault := mgr.EmbeddedVault(); embeddedVault != nil {
		// Embedded dev path: vault is running locally with -dev mode and a
		// known root token. Every cage shares the same token; there is no
		// per-cage scoping. Acceptable because embedded mode is the
		// developer's laptop, where the host trust boundary already
		// dominates whatever Vault would enforce.
		vaultClient, vaultErr := identity.NewVaultTokenClient(identity.VaultTokenConfig{
			Address: embeddedVault.Address(),
			Token:   embeddedVault.RootToken(),
		})
		if vaultErr != nil {
			return fmt.Errorf("creating embedded Vault client: %w", vaultErr)
		}
		healthCtx, cancelHealth := context.WithTimeout(ctx, 5*time.Second)
		if err := vaultClient.Health(healthCtx); err != nil {
			cancelHealth()
			return fmt.Errorf("embedded vault unreachable at %s: %w", embeddedVault.Address(), err)
		}
		cancelHealth()

		secretFetcher = vaultClient
		log.Info("Vault secret fetcher connected (embedded dev token)",
			"addr", embeddedVault.Address())
	}
	if secretFetcher == nil {
		if !cfg.AllowUnisolatedDefault() {
			return fmt.Errorf("no Vault configured: set infrastructure.vault.address, enable embedded Vault, or set cage_runtime.allow_unisolated=true for dev-mode secrets")
		}
		log.Info("WARNING: Vault not configured — cages will use dev secrets (allow_unisolated=true)")
	}

	// --- Cage rootfs builder ---
	//
	// Only required when the Firecracker provisioner is in use. The mock
	// provisioner never touches the rootfs file, so unisolated mode runs
	// happily without one.

	baseRootfs := filepath.Join(embedded.VMDir(), "cage-rootfs.img")
	rootfsWorkDir := filepath.Join(embedded.DataDir(), "rootfs-work")
	if err := os.MkdirAll(rootfsWorkDir, 0755); err != nil {
		return fmt.Errorf("creating rootfs work directory: %w", err)
	}
	if isolated {
		if reason := cage.CheckBaseRootfs(baseRootfs); reason != "" {
			return fmt.Errorf("base rootfs not usable (%s): cages cannot be assembled without it", reason)
		}
		log.Info("base rootfs OK", "path", baseRootfs)
	}
	rootfsBuilder := cage.NewRootfsBuilder(baseRootfs, rootfsWorkDir, version)
	if err := rootfsBuilder.SweepStale(ctx, log); err != nil {
		log.Error(err, "sweeping stale rootfs state — continuing")
	}

	// --- Falco alert reader ---
	//
	// Falco is the runtime behavioral tripwire — it watches syscalls inside
	// each cage and emits JSON alerts on matched rules. The reader connects
	// to its Unix socket. If Falco is missing in production, cages would
	// run without behavioral monitoring, so absence is fatal unless the
	// operator opts into the unisolated runtime.

	var falcoReader *cage.FalcoAlertReader
	falcoSocket := filepath.Join(embedded.RunDir(), "falco", "falco.sock")
	if cfg.Infrastructure.Falco != nil && cfg.Infrastructure.Falco.Socket != "" {
		falcoSocket = cfg.Infrastructure.Falco.Socket
	}

	if reason := cage.CheckFalcoSocket(ctx, falcoSocket); reason != "" {
		if !cfg.AllowUnisolatedDefault() {
			return fmt.Errorf("falco not usable (%s); set cage_runtime.allow_unisolated=true to run cages without behavioral tripwires", reason)
		}
		log.Info("WARNING: Falco unavailable — cages will run without behavioral tripwires",
			"socket", falcoSocket, "reason", reason)
	} else {
		falcoReader = cage.NewFalcoAlertReader(falcoSocket, log)
		log.Info("Falco alert reader configured", "socket", falcoSocket)
	}

	// --- Cage activity implementation ---

	cageActivityImpl := cage.NewActivityImpl(cage.ActivityImplConfig{
		Provisioner:   cageProvisioner,
		Rootfs:        rootfsBuilder,
		Network:       networkEnforcer,
		Validator:     scopeValidator,
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
		Cages:         cageSvc,
		Findings:      findingStore,
		Bus:           findingsBus,
		Coordinator:   findingsCoordinator,
		Fleet:         autoscaler,
		LLMClient:     llmClient,
		Proofs:        proofLib,
		Interventions: iSvc,
		Log:           log,
	})

	// --- gRPC server ---

	var grpcOpts []grpc.ServerOption
	grpcOpts = append(grpcOpts,
		grpc.ChainUnaryInterceptor(
			agentgrpc.RecoveryUnaryInterceptor(log.WithValues("component", "grpc")),
			agentgrpc.LoggingUnaryInterceptor(log.WithValues("component", "grpc")),
		),
		// Caps so a buggy or hostile client cannot exhaust orchestrator
		// resources. 32 MB matches NATS' findings cap; 256 streams covers
		// fleet operators with several concurrent CLIs.
		grpc.MaxRecvMsgSize(32*1024*1024),
		grpc.MaxConcurrentStreams(256),
		grpc.KeepaliveParams(keepalive.ServerParameters{
			Time:    60 * time.Second,
			Timeout: 20 * time.Second,
		}),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
			MinTime:             30 * time.Second,
			PermitWithoutStream: false,
		}),
	)
	switch {
	case cfg.GRPC.UseInternalTLS():
		tlsCfg, tlsErr := agentgrpc.SPIREServerTLS(ctx, "unix://"+spireSocket)
		if tlsErr != nil {
			return fmt.Errorf("configuring internal mTLS for gRPC: %w", tlsErr)
		}
		grpcOpts = append(grpcOpts, grpc.Creds(credentials.NewTLS(tlsCfg)))
		log.Info("gRPC mTLS enabled via internal identity provider")
	case cfg.GRPC.UseFileTLS():
		// File TLS loads cert+key once at startup. Cert rotation requires
		// an orchestrator restart — there is no reload-on-disk-change. The
		// SPIRE-internal branch above handles rotation automatically via
		// the workload API. If you need on-the-fly rotation with operator
		// PKI, switch to internal mode and configure SPIRE upstream.
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

	// Standard gRPC health service so load balancers and grpc_health_probe
	// work without a custom probe path. Mark every registered service as
	// SERVING; future readiness checks (e.g. database reachable) can flip
	// individual entries.
	healthSrv := health.NewServer()
	healthSrv.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)
	healthpb.RegisterHealthServer(grpcServer, healthSrv)

	// gRPC reflection: posture default (dev=on, strict=off), with explicit
	// override via grpc.reflection. Reflection exposes the full service
	// surface to any client that can hit the server.
	if cfg.GRPCReflectionDefault() {
		reflection.Register(grpcServer)
		log.Info("gRPC reflection enabled")
	}

	log.Info("gRPC services registered")

	// --- Temporal workers ---
	//
	// Cage worker concurrency is bounded by the fleet's total cage slots
	// times a small multiplier — Monitor activities run for the cage's
	// full lifetime, so the per-worker activity slot count must not exceed
	// what the fleet can host. Default to 32 when no fleet hosts are
	// registered yet (single-host dev mode); the autoscaler will register
	// real hosts shortly after.
	maxCageActivities := int(poolManager.TotalCageSlots()) * 4
	if maxCageActivities < 32 {
		maxCageActivities = 32
	}

	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "unknown"
	}
	cageIdentity := fmt.Sprintf("agentcage-%s-%s-cage", version, hostname)
	assessmentIdentity := fmt.Sprintf("agentcage-%s-%s-assessment", version, hostname)

	fmt.Println("Registering Temporal workers...")
	cageWorkerLog := log.WithValues("component", "cage-worker")
	cageWorker := worker.New(temporalClient, cage.TaskQueue, worker.Options{
		Identity:                           cageIdentity,
		MaxConcurrentActivityExecutionSize: maxCageActivities,
		// Bound shutdown drain time. Long-running MonitorCage activities
		// can run for hours; without this, Stop() would hang forever
		// during a graceful shutdown. Activities that don't finish in
		// 30 seconds are cancelled via context and Temporal reschedules
		// them on the next worker that comes up.
		WorkerStopTimeout: 30 * time.Second,
		// Root activity context = orchestrator ctx, so a global cancel
		// (shutdown signal, fatal error) propagates into every running
		// activity alongside the WorkerStopTimeout drain.
		BackgroundActivityContext: ctx,
		OnFatalError: func(err error) {
			cageWorkerLog.Error(err, "cage worker fatal error — shutting down")
			cancel()
		},
	})
	cageWorker.RegisterWorkflowWithOptions(cage.CageWorkflow, workflow.RegisterOptions{
		Name: cage.WorkflowName,
	})
	cageActivityImpl.RegisterActivities(cageWorker)

	assessmentWorkerLog := log.WithValues("component", "assessment-worker")
	assessmentWorker := worker.New(temporalClient, assessment.TaskQueue, worker.Options{
		Identity: assessmentIdentity,
		// Assessment activities are mostly orchestration calls (LLM,
		// findings store, intervention emit) — light and fast, so the
		// ceiling is "how many assessments do we expect concurrently."
		MaxConcurrentActivityExecutionSize: 256,
		WorkerStopTimeout:                  30 * time.Second,
		BackgroundActivityContext:          ctx,
		OnFatalError: func(err error) {
			assessmentWorkerLog.Error(err, "assessment worker fatal error — shutting down")
			cancel()
		},
	})
	assessmentWorker.RegisterWorkflowWithOptions(assessment.AssessmentWorkflow, workflow.RegisterOptions{
		Name: assessment.WorkflowName,
	})
	assessmentActivityImpl.RegisterActivities(assessmentWorker)

	// --- Timeout enforcer ---

	enforcerLog := log.WithValues("component", "timeout-enforcer")
	pollInterval := cfg.InterventionPollInterval()
	timeoutEnforcer := intervention.NewTimeoutEnforcer(iQueue, temporalClient, pollInterval, enforcerLog)

	// --- Start workers (BEFORE gRPC) ---
	//
	// Workers must be running before gRPC accepts traffic, otherwise an
	// early CreateAssessment call enqueues a workflow that has no worker
	// to pick it up — caller sees an apparent hang until the workers
	// finish coming online.

	fmt.Println("Starting Temporal workers...")
	if err := cageWorker.Start(); err != nil {
		return fmt.Errorf("starting cage worker: %w", err)
	}
	if err := assessmentWorker.Start(); err != nil {
		// Roll back the cage worker on failure. Stop() can take up to
		// WorkerStopTimeout (30s) but typically returns instantly here
		// since no activities have been dispatched yet.
		cageWorker.Stop()
		cageWorkerLog.Info("cage worker stopped (rollback after assessment worker start failed)")
		return fmt.Errorf("starting assessment worker: %w", err)
	}
	// worker.Start() returns when the SDK has spawned its internal
	// goroutines, NOT when those goroutines have actually registered as
	// pollers with Temporal. Without this gate, gRPC would start
	// accepting CreateAssessment calls and the workflow would enqueue
	// against a task queue with no live pollers — caller hangs until
	// the worker eventually comes online. Block until Temporal reports
	// at least one poller on each task queue.
	temporalNamespace := temporalOpts.Namespace
	if temporalNamespace == "" {
		temporalNamespace = "default"
	}
	for _, queue := range []string{cage.TaskQueue, assessment.TaskQueue} {
		if err := waitForWorkerReady(ctx, temporalClient, temporalNamespace, queue, 10*time.Second); err != nil {
			cageWorker.Stop()
			assessmentWorker.Stop()
			log.Info("workers stopped (rollback after readiness probe failed)", "queue", queue)
			return fmt.Errorf("waiting for worker on task queue %s: %w", queue, err)
		}
	}
	enforcerLog.Info("timeout enforcer started", "interval", pollInterval)
	go func() {
		tErr := timeoutEnforcer.Run(ctx)
		if tErr != nil {
			enforcerLog.Error(tErr, "stopped — triggering orchestrator shutdown")
		} else {
			enforcerLog.Info("stopped")
		}
		// If the enforcer dies for any reason while ctx is still live,
		// the rest of the orchestrator can no longer reap timed-out
		// interventions. Cancel everything so the operator gets a clear
		// shutdown rather than a half-running degraded state.
		if ctx.Err() == nil {
			cancel()
		}
	}()

	// --- Start gRPC ---

	fmt.Printf("Starting gRPC server on %s...\n", grpcAddr)
	if isGlobalBind(grpcAddr) && !cfg.GRPC.TLSEnabled() && !cfg.AllowUnisolatedDefault() {
		return fmt.Errorf("refusing to bind gRPC on %s without TLS: configure grpc.tls or set cage_runtime.allow_unisolated=true for dev", grpcAddr)
	}
	lis, err := net.Listen("tcp", grpcAddr)
	if err != nil {
		if errors.Is(err, syscall.EADDRINUSE) {
			return fmt.Errorf("listening on %s: address already in use — is another agentcage running? (try `agentcage status` or `lsof -i %s`)", grpcAddr, grpcAddr)
		}
		return fmt.Errorf("listening on %s: %w", grpcAddr, err)
	}

	go func() {
		if srvErr := grpcServer.Serve(lis); srvErr != nil {
			log.Error(srvErr, "gRPC server failed")
			cancel()
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

	// Shutdown order: stop accepting new gRPC traffic, then stop workers,
	// then close auxiliary services. Temporal workflows that are mid-flight
	// when workers stop are durable — they will resume on the next start.
	// gRPC requests that started before GracefulStop returns are allowed
	// to complete, so the only window of "incomplete" work is a workflow
	// whose first activity has not yet been picked up by a worker; that
	// case is also safe because Temporal will retry the activity once a
	// worker becomes available again.
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

// buildVaultTLSConfig produces the *tls.Config used to verify Vault's
// server certificate. Mirrors the GRPCConfig.TLS pattern: internal uses the
// SPIRE trust bundle, ca_cert_file uses an operator-provided CA, otherwise
// nil (system trust store).
func buildVaultTLSConfig(ctx context.Context, cfg *config.Config, spireSocket string) (*tls.Config, error) {
	vaultCfg := cfg.Infrastructure.Vault
	if vaultCfg == nil || vaultCfg.TLS == nil {
		return nil, nil
	}
	t := vaultCfg.TLS

	if cfg.VaultSkipVerifyDefault() {
		return &tls.Config{InsecureSkipVerify: true}, nil //nolint:gosec // explicit operator opt-in; rejected by validatePosture in strict mode
	}

	if t.Internal {
		source, err := workloadapi.NewX509Source(ctx, workloadapi.WithClientOptions(
			workloadapi.WithAddr("unix://"+spireSocket),
		))
		if err != nil {
			return nil, fmt.Errorf("opening SPIRE X.509 source for Vault TLS: %w", err)
		}
		// Vault is a server we authenticate; we trust any SVID from our
		// trust domain. Replace AuthorizeAny with a tighter authorizer if
		// you want to pin a specific Vault SPIFFE ID.
		return tlsconfig.MTLSClientConfig(source, source, tlsconfig.AuthorizeAny()), nil
	}

	if t.CACertFile != "" {
		caBytes, err := os.ReadFile(t.CACertFile)
		if err != nil {
			return nil, fmt.Errorf("reading vault ca_cert_file %s: %w", t.CACertFile, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caBytes) {
			return nil, fmt.Errorf("vault ca_cert_file %s: no PEM certs found", t.CACertFile)
		}
		return &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}, nil
	}

	return nil, nil
}

func vaultTLSMode(cfg *config.Config) string {
	vaultCfg := cfg.Infrastructure.Vault
	if vaultCfg == nil || vaultCfg.TLS == nil {
		return "system"
	}
	switch {
	case cfg.VaultSkipVerifyDefault():
		return "insecure-skip-verify"
	case vaultCfg.TLS.Internal:
		return "spire-internal"
	case vaultCfg.TLS.CACertFile != "":
		return "ca-pinned"
	default:
		return "system"
	}
}

// waitForWorkerReady polls Temporal until at least one poller is registered
// on the given task queue, or until the timeout elapses. Closes the
// "Start() returned but worker isn't actually polling yet" race that would
// otherwise let early gRPC requests enqueue workflows nobody picks up.
func waitForWorkerReady(ctx context.Context, c client.Client, namespace, taskQueueName string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		probeCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		resp, err := c.WorkflowService().DescribeTaskQueue(probeCtx, &workflowservice.DescribeTaskQueueRequest{
			Namespace:     namespace,
			TaskQueue:     &taskqueue.TaskQueue{Name: taskQueueName, Kind: enums.TASK_QUEUE_KIND_NORMAL},
			TaskQueueType: enums.TASK_QUEUE_TYPE_WORKFLOW,
		})
		cancel()
		if err == nil && len(resp.GetPollers()) > 0 {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
	}
	return fmt.Errorf("no pollers registered on %s within %s", taskQueueName, timeout)
}

// isGlobalBind reports whether the listen address binds to all interfaces.
// Used to gate the no-TLS startup safety check — loopback-only binds are
// fine without TLS, anything else is not.
func isGlobalBind(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		// Couldn't parse — assume the worst.
		return true
	}
	if host == "" || host == "0.0.0.0" || host == "::" || host == "[::]" {
		return true
	}
	ip := net.ParseIP(host)
	if ip != nil && ip.IsUnspecified() {
		return true
	}
	return false
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
