package main

import (
	"context"
	"fmt"

	pb "github.com/okedeji/agentcage/api/proto"
	"github.com/okedeji/agentcage/internal/config"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	grpcinsecure "google.golang.org/grpc/credentials/insecure"
)

func dialOrchestrator(ctx context.Context, cfg *config.Config) (*grpc.ClientConn, error) {
	addr := cfg.ServerAddress()

	var dialOpts []grpc.DialOption
	if cfg.Server.Insecure {
		dialOpts = append(dialOpts, grpc.WithTransportCredentials(grpcinsecure.NewCredentials()))
	} else if tlsCfg := buildClientTLS(); tlsCfg != nil {
		// Use the CA cert saved by agentcage connect.
		dialOpts = append(dialOpts, grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)))
	} else {
		// No saved CA cert — fall back to system CA pool.
		dialOpts = append(dialOpts, grpc.WithTransportCredentials(
			credentials.NewClientTLSFromCert(nil, "")))
	}

	if cfg.Server.APIKey != "" {
		dialOpts = append(dialOpts, grpc.WithPerRPCCredentials(apiKeyCredentials{
			key: cfg.Server.APIKey, insecure: cfg.Server.Insecure}))
	}

	conn, err := grpc.NewClient(addr, dialOpts...)
	if err != nil {
		return nil, fmt.Errorf("connecting to orchestrator at %s: %w", addr, err)
	}

	pingCtx, cancel := context.WithTimeout(ctx, cfg.GRPC.ReadyProbeTimeoutOrDefault())
	defer cancel()

	control := pb.NewControlServiceClient(conn)
	if _, err := control.Ping(pingCtx, &pb.PingRequest{}); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("orchestrator not reachable at %s (run 'agentcage init' first): %w", addr, err)
	}
	return conn, nil
}

type apiKeyCredentials struct {
	key      string
	insecure bool
}

func (a apiKeyCredentials) GetRequestMetadata(_ context.Context, _ ...string) (map[string]string, error) {
	return map[string]string{"authorization": "Bearer " + a.key}, nil
}

func (a apiKeyCredentials) RequireTransportSecurity() bool {
	return !a.insecure
}
