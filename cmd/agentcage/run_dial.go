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

	// When no server config was explicitly set (no `agentcage connect`
	// was run), default to localhost insecure. This makes client
	// commands work immediately after `agentcage init` on the same
	// machine — like docker ps after dockerd starts.
	insecure := cfg.Server.Insecure
	if cfg.Server.Address == "" {
		insecure = true
	}

	var dialOpts []grpc.DialOption
	if insecure {
		dialOpts = append(dialOpts, grpc.WithTransportCredentials(grpcinsecure.NewCredentials()))
	} else if tlsCfg := buildClientTLS(); tlsCfg != nil {
		dialOpts = append(dialOpts, grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)))
	} else {
		dialOpts = append(dialOpts, grpc.WithTransportCredentials(
			credentials.NewClientTLSFromCert(nil, "")))
	}

	if cfg.Server.APIKey != "" {
		dialOpts = append(dialOpts, grpc.WithPerRPCCredentials(apiKeyCredentials{
			key: cfg.Server.APIKey, insecure: insecure}))
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
