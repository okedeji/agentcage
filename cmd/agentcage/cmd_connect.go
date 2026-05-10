package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	pb "github.com/okedeji/agentcage/api/proto"
	"github.com/okedeji/agentcage/internal/config"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	grpcinsecure "google.golang.org/grpc/credentials/insecure"
	"gopkg.in/yaml.v3"
)

func cmdConnect(args []string) {
	// Reorder args so flags after the address are parsed correctly.
	// "connect addr --insecure" → "--insecure addr"
	var reordered []string
	var positional []string
	for _, a := range args {
		if len(a) > 0 && a[0] == '-' {
			reordered = append(reordered, a)
		} else {
			positional = append(positional, a)
		}
	}
	reordered = append(reordered, positional...)

	fs := flag.NewFlagSet("connect", flag.ExitOnError)
	apiKey := fs.String("api-key", "", "API key for authentication (required)")
	insecureFlag := fs.Bool("insecure", false, "skip TLS (localhost/dev only)")
	_ = fs.Parse(reordered)

	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "usage: agentcage connect <address> --api-key <key>")
		fmt.Fprintln(os.Stderr, "\nExamples:")
		fmt.Fprintln(os.Stderr, "  agentcage connect orchestrator.prod:9090 --api-key <key>")
		fmt.Fprintln(os.Stderr, "  agentcage connect localhost:9090 --api-key <key> --insecure")
		os.Exit(1)
	}

	addr := fs.Arg(0)

	if *apiKey == "" && !*insecureFlag {
		fmt.Fprintln(os.Stderr, "error: --api-key is required (use --insecure to connect without auth in dev mode)")
		os.Exit(1)
	}

	// First connection: skip server verification to fetch the CA cert
	// (trust-on-first-use). Subsequent connections verify against the
	// saved CA.
	conn, err := connectInitial(addr, *apiKey, *insecureFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	defer func() { _ = conn.Close() }()

	fmt.Println("Fetching config and CA certificate from orchestrator...")
	resp, fetchErr := fetchConfigAndCA(conn)
	if fetchErr != nil {
		fmt.Fprintf(os.Stderr, "warning: could not fetch config: %v\n", fetchErr)
	}

	home := config.HomeDir()
	if resp != nil && len(resp.GetCaCert()) > 0 {
		caPath := filepath.Join(home, "ca.pem")
		if err := os.MkdirAll(home, 0755); err != nil {
			fmt.Fprintf(os.Stderr, "error creating %s: %v\n", home, err)
			os.Exit(1)
		}
		if err := os.WriteFile(caPath, resp.GetCaCert(), 0644); err != nil {
			fmt.Fprintf(os.Stderr, "error saving CA cert: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("CA certificate saved to %s\n", caPath)
	}

	server := config.ServerConfig{Address: addr, APIKey: *apiKey}
	if *insecureFlag {
		server.Insecure = true
	}

	var remoteConfig []byte
	if resp != nil {
		remoteConfig = resp.GetConfigYaml()
	}

	if err := writeConnectConfig(server, remoteConfig); err != nil {
		fmt.Fprintf(os.Stderr, "error saving config: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Connected to %s\n", addr)
	fmt.Printf("Config saved to %s\n", config.DefaultPath())
}

// connectInitial connects with TLS but skips server cert verification
// for the first connection. This is trust-on-first-use: we fetch the
// CA cert from the server and save it for future connections.
func connectInitial(addr, apiKey string, insecureMode bool) (*grpc.ClientConn, error) {
	var dialOpts []grpc.DialOption

	if insecureMode {
		dialOpts = append(dialOpts, grpc.WithTransportCredentials(grpcinsecure.NewCredentials()))
	} else {
		// Skip verification for initial connect. The server's CA cert
		// is fetched via GetConfig and saved for subsequent connections.
		tlsCfg := &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
		}
		dialOpts = append(dialOpts, grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)))
	}

	dialOpts = append(dialOpts, grpc.WithPerRPCCredentials(apiKeyCredentials{
		key: apiKey, insecure: insecureMode}))

	conn, err := grpc.NewClient(addr, dialOpts...)
	if err != nil {
		return nil, fmt.Errorf("connecting to %s: %w", addr, err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client := pb.NewControlServiceClient(conn)
	if _, err := client.Ping(ctx, &pb.PingRequest{}); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("orchestrator not reachable at %s: %w", addr, err)
	}
	return conn, nil
}

func fetchConfigAndCA(conn *grpc.ClientConn) (*pb.GetConfigResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client := pb.NewControlServiceClient(conn)
	return client.GetConfig(ctx, &pb.GetConfigRequest{})
}

func writeConnectConfig(server config.ServerConfig, remoteConfigYAML []byte) error {
	path := config.DefaultPath()

	var cfg config.Config
	if remoteConfigYAML != nil {
		if err := yaml.Unmarshal(remoteConfigYAML, &cfg); err != nil {
			return fmt.Errorf("parsing remote config: %w", err)
		}
	} else if data, err := os.ReadFile(path); err == nil {
		if parseErr := yaml.Unmarshal(data, &cfg); parseErr != nil {
			return fmt.Errorf("parsing existing config %s: %w", path, parseErr)
		}
	}

	cfg.Server = server

	data, err := yaml.Marshal(&cfg)
	if err != nil {
		return fmt.Errorf("marshaling config: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("creating config directory: %w", err)
	}
	return os.WriteFile(path, data, 0600)
}

// buildClientTLS loads the saved CA cert for server verification.
// Returns nil if no CA cert is saved (insecure mode).
func buildClientTLS() *tls.Config {
	caPath := filepath.Join(config.HomeDir(), "ca.pem")
	ca, err := os.ReadFile(caPath)
	if err != nil {
		return nil
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return nil
	}
	return &tls.Config{
		RootCAs:    pool,
		MinVersion: tls.VersionTLS12,
	}
}
