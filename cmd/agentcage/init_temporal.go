package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"time"

	"github.com/go-logr/logr"
	enums "go.temporal.io/api/enums/v1"
	taskqueue "go.temporal.io/api/taskqueue/v1"
	"go.temporal.io/api/workflowservice/v1"
	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/worker"
	"go.temporal.io/sdk/workflow"

	"github.com/okedeji/agentcage/internal/assessment"
	"github.com/okedeji/agentcage/internal/cage"
	"github.com/okedeji/agentcage/internal/config"
	"github.com/okedeji/agentcage/internal/identity"
	agentgrpc "github.com/okedeji/agentcage/internal/grpc"
	"github.com/okedeji/agentcage/internal/metrics"
)

func resolveTemporalAddr(cfg *config.Config) string {
	if cfg.Infrastructure.IsExternalTemporal() {
		return cfg.Infrastructure.Temporal.Address
	}
	return "localhost:17233"
}

// Returns the resolved namespace so the readiness probe doesn't
// recompute the "default" fallback.
func connectTemporal(ctx context.Context, cfg *config.Config, secrets identity.SecretReader, spireSocket string, log logr.Logger) (client.Client, string, error) {
	temporalAddr := resolveTemporalAddr(cfg)

	fmt.Println("Connecting to Temporal...")
	opts := client.Options{
		HostPort: temporalAddr,
		// SDK metrics through OTel so worker internals land in the
		// same pipeline as everything else.
		MetricsHandler: metrics.NewTemporalMetricsHandler(),
	}

	if tc := cfg.Infrastructure.Temporal; tc != nil {
		if tc.Namespace != "" {
			opts.Namespace = tc.Namespace
		}
		if tc.TLS != nil {
			switch {
			case tc.TLS.Internal:
				internalTLS, spireErr := agentgrpc.SPIREClientTLS(ctx, "unix://"+spireSocket)
				if spireErr != nil {
					return nil, "", fmt.Errorf("configuring internal mTLS for Temporal: %w", spireErr)
				}
				opts.ConnectionOptions = client.ConnectionOptions{TLS: internalTLS}
				log.Info("Temporal mTLS enabled via internal identity provider")
			case tc.TLS.CertFile != "":
				cert, tlsErr := tls.LoadX509KeyPair(tc.TLS.CertFile, tc.TLS.KeyFile)
				if tlsErr != nil {
					return nil, "", fmt.Errorf("loading Temporal TLS cert: %w", tlsErr)
				}
				tlsCfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
				if tc.TLS.CAFile != "" {
					caCert, caErr := os.ReadFile(tc.TLS.CAFile)
					if caErr != nil {
						return nil, "", fmt.Errorf("reading Temporal CA file: %w", caErr)
					}
					pool := x509.NewCertPool()
					pool.AppendCertsFromPEM(caCert)
					tlsCfg.RootCAs = pool
				}
				opts.ConnectionOptions = client.ConnectionOptions{TLS: tlsCfg}
				log.Info("Temporal mTLS enabled", "cert", tc.TLS.CertFile)
			}
		}
		if secrets != nil {
			if apiKey, _ := identity.ReadSecretValue(ctx, secrets, identity.PathTemporalKey); apiKey != "" {
				opts.Credentials = client.NewAPIKeyStaticCredentials(apiKey)
				log.Info("Temporal API key auth enabled")
			}
		}
	}

	c, err := client.Dial(opts)
	if err != nil {
		return nil, "", fmt.Errorf("connecting to Temporal at %s: %w", temporalAddr, err)
	}

	namespace := opts.Namespace
	if namespace == "" {
		namespace = "default"
	}
	return c, namespace, nil
}

// Cage slots are sized off fleet capacity so a worker can't accept
// more cages than the host can run.
func buildTemporalWorkers(
	ctx context.Context,
	cancel context.CancelFunc,
	temporal client.Client,
	totalCageSlots int32,
	cageActivities *cage.ActivityImpl,
	assessmentActivities *assessment.ActivityImpl,
	log logr.Logger,
) (worker.Worker, worker.Worker) {
	// Cage worker concurrency is bounded by fleet capacity. Monitor
	// activities run for the cage's full lifetime, so the slot count
	// must not exceed what the fleet can host. Default 32 for
	// single-host dev; the autoscaler registers real hosts later.
	maxCageActivities := int(totalCageSlots) * 4
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
	cageWorker := worker.New(temporal, cage.TaskQueue, worker.Options{
		Identity:                           cageIdentity,
		MaxConcurrentActivityExecutionSize: maxCageActivities,
		// Bound the drain. MonitorCage runs for hours; without this
		// Stop() hangs forever. Activities that don't finish in 30s
		// get cancelled and Temporal reschedules them.
		WorkerStopTimeout: 30 * time.Second,
		// Root context is the orchestrator's so a global cancel
		// propagates into every running activity alongside the drain.
		BackgroundActivityContext: ctx,
		OnFatalError: func(err error) {
			cageWorkerLog.Error(err, "cage worker fatal error, shutting down")
			cancel()
		},
	})
	cageWorker.RegisterWorkflowWithOptions(cage.CageWorkflow, workflow.RegisterOptions{
		Name: cage.WorkflowName,
	})
	cageActivities.RegisterActivities(cageWorker)

	assessmentWorkerLog := log.WithValues("component", "assessment-worker")
	assessmentWorker := worker.New(temporal, assessment.TaskQueue, worker.Options{
		Identity: assessmentIdentity,
		// Assessment activities are mostly orchestration calls, so
		// the ceiling is just concurrent assessment count.
		MaxConcurrentActivityExecutionSize: 256,
		WorkerStopTimeout:                  30 * time.Second,
		BackgroundActivityContext:          ctx,
		OnFatalError: func(err error) {
			assessmentWorkerLog.Error(err, "assessment worker fatal error, shutting down")
			cancel()
		},
	})
	assessmentWorker.RegisterWorkflowWithOptions(assessment.AssessmentWorkflow, workflow.RegisterOptions{
		Name: assessment.WorkflowName,
	})
	assessmentActivities.RegisterActivities(assessmentWorker)

	return cageWorker, assessmentWorker
}

// Without the poller readiness probe, gRPC would accept
// CreateAssessment before any worker is polling, and the caller
// hangs until one wakes up.
func startTemporalWorkers(
	ctx context.Context,
	temporal client.Client,
	namespace string,
	cageWorker, assessmentWorker worker.Worker,
	log logr.Logger,
) error {
	fmt.Println("Starting Temporal workers...")
	if err := cageWorker.Start(); err != nil {
		return fmt.Errorf("starting cage worker: %w", err)
	}
	if err := assessmentWorker.Start(); err != nil {
		// Roll back the cage worker. Stop() can take up to 30s but
		// returns instantly here, no activities have dispatched yet.
		cageWorker.Stop()
		log.Info("cage worker stopped (rollback after assessment worker start failed)")
		return fmt.Errorf("starting assessment worker: %w", err)
	}

	// worker.Start() returns when goroutines are spawned, not when
	// they've registered as pollers.
	for _, queue := range []string{cage.TaskQueue, assessment.TaskQueue} {
		if err := waitForWorkerReady(ctx, temporal, namespace, queue, 10*time.Second); err != nil {
			cageWorker.Stop()
			assessmentWorker.Stop()
			log.Info("workers stopped (rollback after readiness probe failed)", "queue", queue)
			return fmt.Errorf("waiting for worker on task queue %s: %w", queue, err)
		}
	}
	return nil
}

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
