package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"syscall"
	"time"

	"github.com/go-logr/logr"
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/reflection"

	"github.com/okedeji/agentcage/internal/config"
	"github.com/okedeji/agentcage/internal/ui"
	"github.com/okedeji/agentcage/internal/embedded"
	agentgrpc "github.com/okedeji/agentcage/internal/grpc"
)

func buildGRPCServer(
	ctx context.Context,
	cfg *config.Config,
	services agentgrpc.Services,
	log logr.Logger,
) (*grpc.Server, error) {
	opts := []grpc.ServerOption{
		grpc.StatsHandler(otelgrpc.NewServerHandler()),
		grpc.ChainUnaryInterceptor(
			agentgrpc.RecoveryUnaryInterceptor(log.WithValues("component", "grpc")),
			agentgrpc.AuthUnaryInterceptor(services.ConfigServer, false, log.WithValues("component", "grpc-auth")),
			agentgrpc.LoggingUnaryInterceptor(log.WithValues("component", "grpc")),
		),
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

	if cfg.GRPC.TLSEnabled() {
		hostname := cfg.GRPC.LetsEncryptDomain()
		if hostname == "" {
			host, _, _ := net.SplitHostPort(cfg.GRPCListenAddr())
			if host == "" || host == "0.0.0.0" || host == "::" {
				hostname = "localhost"
			} else {
				hostname = host
			}
		}

		tlsDir := filepath.Join(embedded.DataDir(), "tls")
		certs, err := agentgrpc.EnsureTLSCerts(tlsDir, hostname)
		if err != nil {
			return nil, fmt.Errorf("generating TLS certificates: %w", err)
		}

		tlsCfg, err := agentgrpc.LoadServerTLS(certs)
		if err != nil {
			return nil, fmt.Errorf("loading TLS certificates: %w", err)
		}

		caPEM, _ := agentgrpc.ReadCACert(certs)
		services.CACert = caPEM

		opts = append(opts, grpc.Creds(credentials.NewTLS(tlsCfg)))
		log.Info("gRPC TLS enabled (self-signed CA)", "hostname", hostname, "dir", tlsDir)
	}

	server := grpc.NewServer(opts...)
	agentgrpc.Register(server, services)

	healthSrv := health.NewServer()
	healthSrv.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)
	healthpb.RegisterHealthServer(server, healthSrv)

	if cfg.GRPCReflectionDefault() {
		reflection.Register(server)
		log.Info("gRPC reflection enabled")
	}

	log.Info("gRPC services registered")
	return server, nil
}

func startGRPCListener(grpcAddr string, cfg *config.Config, log logr.Logger) (net.Listener, bool, error) {
	ui.Step("Starting gRPC server")
	if isGlobalBind(grpcAddr) && !cfg.GRPC.TLSEnabled() && cfg.Posture == config.PostureStrict {
		return nil, false, fmt.Errorf("refusing to bind gRPC on %s without TLS in strict posture: configure grpc.tls or set posture=dev", grpcAddr)
	}
	lis, activated, err := agentgrpc.AcquireListener(grpcAddr)
	if err != nil {
		if errors.Is(err, syscall.EADDRINUSE) {
			port := grpcAddr
			if _, p, splitErr := net.SplitHostPort(grpcAddr); splitErr == nil {
				port = p
			}
			return nil, false, fmt.Errorf("listening on %s: address already in use. Run `lsof -i :%s` to find the process", grpcAddr, port)
		}
		return nil, false, fmt.Errorf("listening on %s: %w", grpcAddr, err)
	}
	if activated {
		log.Info("gRPC listener inherited from systemd socket activation", "addr", lis.Addr().String())
	}
	return lis, activated, nil
}

func serveGRPC(server *grpc.Server, lis net.Listener, cancel context.CancelFunc, log logr.Logger) {
	go func() {
		if srvErr := server.Serve(lis); srvErr != nil && !errors.Is(srvErr, grpc.ErrServerStopped) {
			log.Error(srvErr, "gRPC server failed")
			cancel()
		}
	}()
}

func waitForGRPCReady(ctx context.Context, cfg *config.Config, grpcAddr string) error {
	readyCtx, readyCancel := context.WithTimeout(ctx, cfg.GRPC.ReadyProbeTimeoutOrDefault())
	defer readyCancel()
	return agentgrpc.WaitForReady(readyCtx, grpcAddr)
}

func isGlobalBind(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return true
	}
	if host == "" || host == "0.0.0.0" || host == "::" || host == "[::]" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsUnspecified()
}
