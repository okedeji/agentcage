package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-logr/logr"
	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/worker"
	"google.golang.org/grpc"

	agentcage "github.com/okedeji/agentcage"
	pb "github.com/okedeji/agentcage/api/proto"
	"github.com/okedeji/agentcage/internal/assessment"
	"github.com/okedeji/agentcage/internal/cage"
	"github.com/okedeji/agentcage/internal/config"
	"github.com/okedeji/agentcage/internal/enforcement"
	"github.com/okedeji/agentcage/internal/fleet"
	"github.com/okedeji/agentcage/internal/intervention"
	proxylog "github.com/okedeji/agentcage/internal/log"
	"github.com/okedeji/agentcage/internal/metrics"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "orchestrator: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	configFile := flag.String("config", "", "path to agentcage.yaml override file")
	temporalAddr := flag.String("temporal-addr", "localhost:7233", "Temporal server address")
	grpcAddr := flag.String("grpc-addr", ":9090", "gRPC server listen address")
	policyDir := flag.String("policy-dir", "policies/rego", "path to OPA Rego policy directory")
	dev := flag.Bool("dev", false, "enable development mode (human-readable logs)")
	flag.Parse()

	// --- Configuration ---

	cfg, err := config.Default(agentcage.DefaultConfigYAML)
	if err != nil {
		return fmt.Errorf("loading default config: %w", err)
	}

	if *configFile != "" {
		override, err := config.Load(*configFile)
		if err != nil {
			return fmt.Errorf("loading config override from %s: %w", *configFile, err)
		}
		cfg = config.Merge(cfg, override)
	}

	// --- Logger ---

	var log logr.Logger
	if *dev {
		log, err = proxylog.NewDev()
	} else {
		log, err = proxylog.New()
	}
	if err != nil {
		return fmt.Errorf("creating logger: %w", err)
	}
	log = log.WithValues("component", "orchestrator")

	// --- Metrics ---

	if err := metrics.Init(); err != nil {
		return fmt.Errorf("initializing metrics: %w", err)
	}

	// --- OPA policy engine ---

	opaEngine, err := enforcement.NewOPAEngine(*policyDir)
	if err != nil {
		return fmt.Errorf("creating OPA engine from %s: %w", *policyDir, err)
	}

	// --- Temporal client ---

	temporalClient, err := client.Dial(client.Options{
		HostPort: *temporalAddr,
	})
	if err != nil {
		return fmt.Errorf("connecting to Temporal at %s: %w", *temporalAddr, err)
	}
	defer temporalClient.Close()

	// --- Domain servers ---

	// Cage validator uses both Go-level validation and OPA policy evaluation.
	cageValidator := func(c cage.Config) error {
		if err := enforcement.ValidateCageConfig(c, cfg); err != nil {
			return err
		}
		decision, err := opaEngine.EvaluateCageConfig(context.Background(), c)
		if err != nil {
			return fmt.Errorf("evaluating cage config policy: %w", err)
		}
		if !decision.Allowed {
			return fmt.Errorf("cage config rejected by policy: %s", decision.Reason)
		}
		scopeDecision, err := opaEngine.EvaluateScope(context.Background(), c.Scope, cfg.Infrastructure.InfraHosts)
		if err != nil {
			return fmt.Errorf("evaluating scope policy: %w", err)
		}
		if !scopeDecision.Allowed {
			return fmt.Errorf("scope rejected by policy: %s", scopeDecision.Reason)
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

	// --- gRPC server ---

	grpcServer := grpc.NewServer()

	// Proto service registration requires adapter types that bridge our
	// domain servers to the generated gRPC interfaces. Until these adapters
	// are built, we register the gRPC server without service implementations.
	// The domain servers are ready — only the proto-to-domain mapping layer
	// is missing. For now, log that the servers are wired and available.
	_ = pb.CageService_ServiceDesc
	_ = cageServer
	_ = assessmentServer
	_ = iServer
	_ = fleetServer
	_ = configServer

	// --- Temporal workers ---

	cageWorker := worker.New(temporalClient, cage.TaskQueue, worker.Options{})
	cageWorker.RegisterWorkflow(cage.CageWorkflow)

	assessmentWorker := worker.New(temporalClient, assessment.TaskQueue, worker.Options{})
	assessmentWorker.RegisterWorkflow(assessment.AssessmentWorkflow)

	// --- Timeout enforcer ---

	timeoutEnforcer := intervention.NewTimeoutEnforcer(iQueue, temporalClient, 30*time.Second, log.WithValues("component", "timeout-enforcer"))

	// --- Graceful shutdown ---

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// --- Start gRPC server ---

	lis, err := net.Listen("tcp", *grpcAddr)
	if err != nil {
		return fmt.Errorf("listening on %s: %w", *grpcAddr, err)
	}

	go func() {
		log.Info("gRPC server listening", "addr", *grpcAddr)
		if err := grpcServer.Serve(lis); err != nil {
			log.Error(err, "gRPC server failed")
			cancel()
		}
	}()

	// --- Start Temporal workers ---

	errCh := make(chan error, 2)

	go func() {
		if err := cageWorker.Run(worker.InterruptCh()); err != nil {
			errCh <- fmt.Errorf("cage worker: %w", err)
		}
	}()

	go func() {
		if err := assessmentWorker.Run(worker.InterruptCh()); err != nil {
			errCh <- fmt.Errorf("assessment worker: %w", err)
		}
	}()

	go func() {
		if err := timeoutEnforcer.Run(ctx); err != nil {
			log.Error(err, "timeout enforcer stopped with error")
		}
	}()

	log.Info("orchestrator started",
		"temporal_addr", *temporalAddr,
		"grpc_addr", *grpcAddr,
		"policy_dir", *policyDir,
		"dev_mode", *dev,
	)

	// --- Wait for shutdown ---

	select {
	case sig := <-sigCh:
		log.Info("received signal, shutting down", "signal", sig.String())
	case err := <-errCh:
		log.Error(err, "worker failed, shutting down")
	case <-ctx.Done():
	}

	grpcServer.GracefulStop()
	cancel()

	cageWorker.Stop()
	assessmentWorker.Stop()

	log.Info("orchestrator stopped")
	return nil
}
