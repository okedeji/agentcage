package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"time"

	pb "github.com/okedeji/agentcage/api/proto"
	"github.com/okedeji/agentcage/internal/config"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	grpcinsecure "google.golang.org/grpc/credentials/insecure"
)

const defaultPingTimeout = 5 * time.Second

func dialOrchestrator(ctx context.Context, cfg *config.Config) (*grpc.ClientConn, error) {
	addr := cfg.ServerAddress()

	creds, err := buildClientCredentials(cfg)
	if err != nil {
		return nil, fmt.Errorf("building TLS credentials: %w", err)
	}

	dialOpts := []grpc.DialOption{grpc.WithTransportCredentials(creds)}
	if cfg.Server.APIKey != "" {
		dialOpts = append(dialOpts, grpc.WithPerRPCCredentials(apiKeyCredentials{key: cfg.Server.APIKey, insecure: cfg.Server.Insecure}))
	}

	conn, err := grpc.NewClient(addr, dialOpts...)
	if err != nil {
		return nil, fmt.Errorf("connecting to orchestrator at %s: %w", addr, err)
	}

	pingTimeout := defaultPingTimeout
	if cfg.GRPC.ReadyProbeTimeoutOrDefault() > 0 {
		pingTimeout = cfg.GRPC.ReadyProbeTimeoutOrDefault()
	}
	pingCtx, cancel := context.WithTimeout(ctx, pingTimeout)
	defer cancel()

	control := pb.NewControlServiceClient(conn)
	if _, err := control.Ping(pingCtx, &pb.PingRequest{}); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("orchestrator not reachable at %s (run 'agentcage init' first): %w", addr, err)
	}
	return conn, nil
}

// Plaintext when no TLS is configured, which is fine for localhost/dev.
func buildClientCredentials(cfg *config.Config) (credentials.TransportCredentials, error) {
	t := cfg.Server.TLS
	if cfg.Server.Insecure || t == nil {
		return grpcinsecure.NewCredentials(), nil
	}

	if t.CertFile != "" && t.CAFile == "" {
		fmt.Fprintln(os.Stderr, "warning: server.tls has cert_file but no ca_file; the system CA pool will be used for server verification")
	}

	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS13}

	if t.CertFile != "" && t.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(t.CertFile, t.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("loading client cert %s: %w", t.CertFile, err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}

	if t.CAFile != "" {
		ca, err := os.ReadFile(t.CAFile)
		if err != nil {
			return nil, fmt.Errorf("reading CA file %s: %w", t.CAFile, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(ca) {
			return nil, fmt.Errorf("CA file %s: no PEM certs found", t.CAFile)
		}
		tlsCfg.RootCAs = pool
	}

	return credentials.NewTLS(tlsCfg), nil
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
