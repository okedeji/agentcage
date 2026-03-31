package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/go-logr/logr"
	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/worker"
	"google.golang.org/grpc"

	"github.com/okedeji/agentcage/internal/assessment"
	"github.com/okedeji/agentcage/internal/cage"
	"github.com/okedeji/agentcage/internal/config"
	"github.com/okedeji/agentcage/internal/embedded"
	"github.com/okedeji/agentcage/internal/enforcement"
	"github.com/okedeji/agentcage/internal/fleet"
	"github.com/okedeji/agentcage/internal/gateway"
	"github.com/okedeji/agentcage/internal/intervention"
	proxylog "github.com/okedeji/agentcage/internal/log"
	"github.com/okedeji/agentcage/internal/metrics"
)

func cmdInit(args []string) {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	configFile := fs.String("config", "", "path to config YAML override file")
	grpcAddr := fs.String("grpc-addr", ":9090", "gRPC server listen address")
	dev := fs.Bool("dev", false, "enable development mode")
	_ = fs.Parse(args)

	if err := runInit(*configFile, *grpcAddr, *dev); err != nil {
		fmt.Fprintf(os.Stderr, "agentcage init: %v\n", err)
		os.Exit(1)
	}
}

func runInit(configFile, grpcAddr string, dev bool) error {
	// --- Configuration ---

	cfg := config.Defaults()
	if configFile != "" {
		override, err := config.Load(configFile)
		if err != nil {
			return fmt.Errorf("loading config override: %w", err)
		}
		cfg = config.Merge(cfg, override)
	}

	// --- Logger ---

	var (
		log    logr.Logger
		logErr error
	)
	if dev {
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

	fmt.Println("\nStarting embedded services...")
	if err := mgr.Start(ctx); err != nil {
		return fmt.Errorf("starting embedded services: %w", err)
	}

	// --- Metrics ---

	if err := metrics.Init(); err != nil {
		return fmt.Errorf("initializing metrics: %w", err)
	}

	// --- OPA policy engine (generated from config) ---

	modules := enforcement.GenerateRegoModules(cfg)
	opaEngine, err := enforcement.NewOPAEngineFromModules(modules)
	if err != nil {
		return fmt.Errorf("creating OPA engine: %w", err)
	}

	// --- Falco rules (generated from config) ---

	_, tripwires := enforcement.GenerateFalcoRules(cfg.Monitoring)
	_ = tripwires // Used by cage monitor activity when Falco alerts arrive

	// --- Temporal client ---

	temporalAddr := "localhost:17233"
	if cfg.Infrastructure.IsExternalTemporal() {
		temporalAddr = cfg.Infrastructure.Temporal.Address
	}

	temporalClient, err := client.Dial(client.Options{
		HostPort: temporalAddr,
	})
	if err != nil {
		return fmt.Errorf("connecting to Temporal at %s: %w", temporalAddr, err)
	}
	defer temporalClient.Close()

	// --- Domain servers ---

	cageValidator := func(c cage.Config) error {
		if validErr := enforcement.ValidateCageConfig(c, cfg); validErr != nil {
			return validErr
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
	cageServer := cage.NewServer(temporalClient, cageValidator)
	assessmentServer := assessment.NewServer(temporalClient)

	iStore := intervention.NewMemStore()
	notifier := &intervention.NoopNotifier{}
	iQueue := intervention.NewQueue(iStore, notifier, log.WithValues("component", "intervention-queue"))
	iServer := intervention.NewServer(iQueue, temporalClient, log.WithValues("component", "intervention-server"))

	poolManager := fleet.NewPoolManager()
	demandLedger := fleet.NewDemandLedger()
	fleetServer := fleet.NewServer(poolManager, demandLedger, log.WithValues("component", "fleet"))

	configServer := config.NewConfigServer(cfg)

	// --- LLM client (for coordinator) ---

	meter := gateway.NewTokenMeter()
	budgetEnforcer := gateway.NewBudgetEnforcer(meter)
	var llmClient *gateway.Client
	if cfg.LLM.Endpoint != "" {
		llmClient = gateway.NewClient(cfg.LLM.Endpoint, cfg.LLM.Timeout, meter, budgetEnforcer)
	}

	// --- Playbook library ---

	var playbooks *assessment.PlaybookLibrary
	playbookDir := filepath.Join("playbooks", "validation")
	if _, statErr := os.Stat(playbookDir); statErr == nil {
		var loadErr error
		playbooks, loadErr = assessment.LoadPlaybooks(playbookDir)
		if loadErr != nil {
			log.Error(loadErr, "loading playbooks — continuing without playbooks")
		}
	}

	// --- Cage activity implementation ---

	cageProvisioner := cage.NewLocalProvisioner()
	networkEnforcer := enforcement.NewNFTablesEnforcer(log)

	cageActivityImpl := cage.NewActivityImpl(cage.ActivityImplConfig{
		Provisioner: cageProvisioner,
		Network:     networkEnforcer,
		Log:         log,
	})

	// --- Assessment activity implementation ---

	assessmentActivityImpl := assessment.NewActivityImpl(assessment.ActivityImplConfig{
		Cages:     cageServer,
		LLMClient: llmClient,
		Playbooks: playbooks,
		Log:       log,
	})

	// --- gRPC server ---

	grpcServer := grpc.NewServer()

	// Register gRPC services — proto adapters bridge domain servers to
	// generated gRPC interfaces. Full registration requires adapter types
	// that implement the pb.Xxx_ServiceServer interfaces by delegating to
	// our domain servers. For now, log availability.
	_ = cageServer
	_ = assessmentServer
	_ = iServer
	_ = fleetServer
	_ = configServer
	log.Info("domain servers ready (gRPC adapter registration pending)")

	// --- Temporal workers ---

	cageWorker := worker.New(temporalClient, cage.TaskQueue, worker.Options{})
	cageWorker.RegisterWorkflow(cage.CageWorkflow)
	cageWorker.RegisterActivity(cageActivityImpl)

	assessmentWorker := worker.New(temporalClient, assessment.TaskQueue, worker.Options{})
	assessmentWorker.RegisterWorkflow(assessment.AssessmentWorkflow)
	assessmentWorker.RegisterActivity(assessmentActivityImpl)

	// --- Timeout enforcer ---

	timeoutEnforcer := intervention.NewTimeoutEnforcer(iQueue, temporalClient, 30*time.Second, log.WithValues("component", "timeout-enforcer"))

	// --- Start gRPC ---

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

	errCh := make(chan error, 2)
	go func() {
		if wErr := cageWorker.Run(worker.InterruptCh()); wErr != nil {
			errCh <- fmt.Errorf("cage worker: %w", wErr)
		}
	}()
	go func() {
		if wErr := assessmentWorker.Run(worker.InterruptCh()); wErr != nil {
			errCh <- fmt.Errorf("assessment worker: %w", wErr)
		}
	}()
	go func() {
		if tErr := timeoutEnforcer.Run(ctx); tErr != nil {
			log.Error(tErr, "timeout enforcer stopped")
		}
	}()

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
	case wErr := <-errCh:
		log.Error(wErr, "worker failed, shutting down")
	case <-ctx.Done():
	}

	fmt.Println("\nShutting down...")

	grpcServer.GracefulStop()
	cancel()
	cageWorker.Stop()
	assessmentWorker.Stop()

	if err := mgr.Stop(context.Background()); err != nil {
		log.Error(err, "error stopping embedded services")
	}

	fmt.Println("agentcage stopped.")
	return nil
}
