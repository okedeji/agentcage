package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"syscall"
	"time"

	"github.com/go-logr/logr"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/reflection"

	"github.com/okedeji/agentcage/internal/config"
	agentgrpc "github.com/okedeji/agentcage/internal/grpc"
)

// reloadableCert is non-nil only on the file-TLS branch; the
// SPIRE-internal branch rotates via the workload API automatically.
func buildGRPCServer(
	ctx context.Context,
	cfg *config.Config,
	spireSocket string,
	trustDomain spiffeid.TrustDomain,
	services agentgrpc.Services,
	log logr.Logger,
) (*grpc.Server, *agentgrpc.ReloadableCert, error) {
	opts := []grpc.ServerOption{
		grpc.ChainUnaryInterceptor(
			agentgrpc.RecoveryUnaryInterceptor(log.WithValues("component", "grpc")),
			agentgrpc.LoggingUnaryInterceptor(log.WithValues("component", "grpc")),
		),
		// Caps so a buggy or hostile client can't exhaust us. 32 MB
		// matches the NATS findings cap. 256 streams covers operators
		// running several concurrent CLIs.
		grpc.MaxRecvMsgSize(32 * 1024 * 1024),
		grpc.MaxConcurrentStreams(256),
		grpc.KeepaliveParams(keepalive.ServerParameters{
			Time:    60 * time.Second,
			Timeout: 20 * time.Second,
		}),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
			MinTime:             30 * time.Second,
			PermitWithoutStream: false,
		}),
	}

	var reloadableCert *agentgrpc.ReloadableCert
	switch {
	case cfg.GRPC.UseInternalTLS():
		tlsCfg, tlsErr := agentgrpc.SPIREServerTLS(ctx, "unix://"+spireSocket, trustDomain)
		if tlsErr != nil {
			return nil, nil, fmt.Errorf("configuring internal mTLS for gRPC: %w", tlsErr)
		}
		opts = append(opts, grpc.Creds(credentials.NewTLS(tlsCfg)))
		log.Info("gRPC mTLS enabled via internal identity provider")
	case cfg.GRPC.UseFileTLS():
		// SIGHUP re-reads the cert+key and swaps atomically. The
		// SPIRE-internal branch above rotates via the workload API
		// and does not need this.
		rc, rcErr := agentgrpc.NewReloadableCert(cfg.GRPC.TLS.CertFile, cfg.GRPC.TLS.KeyFile)
		if rcErr != nil {
			return nil, nil, fmt.Errorf("loading TLS credentials: %w", rcErr)
		}
		reloadableCert = rc
		opts = append(opts, grpc.Creds(credentials.NewTLS(reloadableCert.TLSConfig())))
		log.Info("gRPC TLS enabled (reloadable on SIGHUP)", "cert", cfg.GRPC.TLS.CertFile)
	}

	server := grpc.NewServer(opts...)
	agentgrpc.Register(server, services)

	healthSrv := health.NewServer()
	healthSrv.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)
	healthpb.RegisterHealthServer(server, healthSrv)

	// Reflection: dev posture defaults on, strict off. Exposes the
	// full service surface to anyone who can hit the server.
	if cfg.GRPCReflectionDefault() {
		reflection.Register(server)
		log.Info("gRPC reflection enabled")
	}

	log.Info("gRPC services registered")
	return server, reloadableCert, nil
}

func startGRPCListener(grpcAddr string, cfg *config.Config, log logr.Logger) (net.Listener, bool, error) {
	fmt.Printf("Starting gRPC server on %s...\n", grpcAddr)
	if isGlobalBind(grpcAddr) && !cfg.GRPC.TLSEnabled() && cfg.Posture == config.PostureStrict {
		return nil, false, fmt.Errorf("refusing to bind gRPC on %s without TLS in strict posture: configure grpc.tls or set posture=dev", grpcAddr)
	}
	// Inherit a systemd-activated socket if one is present. Enables
	// zero-downtime restarts and lets systemd bind a privileged port
	// for an unprivileged agentcage. Falls back to net.Listen.
	lis, activated, err := agentgrpc.AcquireListener(grpcAddr)
	if err != nil {
		if errors.Is(err, syscall.EADDRINUSE) {
			port := grpcAddr
			if _, p, splitErr := net.SplitHostPort(grpcAddr); splitErr == nil {
				port = p
			}
			return nil, false, fmt.Errorf("listening on %s: address already in use. Run `lsof -i :%s` to find the process; if it is another agentcage, `agentcage status` will confirm", grpcAddr, port)
		}
		return nil, false, fmt.Errorf("listening on %s: %w", grpcAddr, err)
	}
	if activated {
		log.Info("gRPC listener inherited from systemd socket activation", "addr", lis.Addr().String())
	}
	return lis, activated, nil
}

// ErrServerStopped is the clean shutdown path. Anything else
// cancels the orchestrator.
func serveGRPC(server *grpc.Server, lis net.Listener, cancel context.CancelFunc, log logr.Logger) {
	go func() {
		if srvErr := server.Serve(lis); srvErr != nil && !errors.Is(srvErr, grpc.ErrServerStopped) {
			log.Error(srvErr, "gRPC server failed")
			cancel()
		}
	}()
}

// Without this probe a client connecting before the first accept
// stalls on its first RPC.
func waitForGRPCReady(ctx context.Context, cfg *config.Config, grpcAddr string) error {
	readyCtx, readyCancel := context.WithTimeout(ctx, cfg.GRPC.ReadyProbeTimeoutOrDefault())
	defer readyCancel()
	return agentgrpc.WaitForReady(readyCtx, grpcAddr)
}

func isGlobalBind(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		// Can't parse, assume the worst.
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
