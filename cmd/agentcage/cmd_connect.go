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
	fs := flag.NewFlagSet("connect", flag.ExitOnError)
	certFile := fs.String("cert", "", "client certificate file")
	keyFile := fs.String("key", "", "client private key file")
	caFile := fs.String("ca", "", "CA certificate file for server verification")
	apiKey := fs.String("api-key", "", "API key for authentication")
	insecureFlag := fs.Bool("insecure", false, "skip TLS (localhost/dev only)")
	_ = fs.Parse(args)

	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "usage: agentcage connect <address> [options]")
		fmt.Fprintln(os.Stderr, "\nExamples:")
		fmt.Fprintln(os.Stderr, "  agentcage connect orchestrator.prod:9090 --cert client.crt --key client.key --ca ca.pem")
		fmt.Fprintln(os.Stderr, "  agentcage connect orchestrator.prod:9090 --api-key <key> --ca ca.pem")
		fmt.Fprintln(os.Stderr, "  agentcage connect orchestrator.prod:9090 --api-key <key> --insecure")
		fmt.Fprintln(os.Stderr, "  agentcage connect localhost:9090 --insecure")
		os.Exit(1)
	}

	addr := fs.Arg(0)

	if !*insecureFlag && *caFile == "" && *apiKey == "" && *certFile == "" {
		fmt.Fprintln(os.Stderr, "error: specify --ca <file> for TLS, --api-key for key auth, or --insecure for plaintext")
		os.Exit(1)
	}

	conn, err := connectOrchestrator(addr, *certFile, *keyFile, *caFile, *apiKey, *insecureFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	defer func() { _ = conn.Close() }()

	fmt.Println("Fetching operator config from orchestrator...")
	remoteConfig, fetchErr := fetchRemoteConfig(conn)
	if fetchErr != nil {
		fmt.Fprintf(os.Stderr, "warning: could not fetch config: %v (connection saved without config)\n", fetchErr)
	}

	home := config.HomeDir()
	var savedCert, savedKey, savedCA string
	if *certFile != "" {
		savedCert = copyCertFile(*certFile, home, "client.crt")
	}
	if *keyFile != "" {
		savedKey = copyCertFile(*keyFile, home, "client.key")
	}
	if *caFile != "" {
		savedCA = copyCertFile(*caFile, home, "ca.pem")
	}

	server := config.ServerConfig{Address: addr}
	if *insecureFlag {
		server.Insecure = true
	} else if savedCA != "" || savedCert != "" {
		server.TLS = &config.ClientTLSConfig{
			CertFile: savedCert,
			KeyFile:  savedKey,
			CAFile:   savedCA,
		}
	}
	if *apiKey != "" {
		server.APIKey = *apiKey
	}

	if err := writeConnectConfig(server, remoteConfig); err != nil {
		fmt.Fprintf(os.Stderr, "error saving config: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Connected to %s\n", addr)
	if remoteConfig != nil {
		fmt.Println("Operator config synced from orchestrator.")
	}
	fmt.Printf("Config saved to %s\n", config.DefaultPath())
}

func connectOrchestrator(addr, certFile, keyFile, caFile, apiKey string, insecure bool) (*grpc.ClientConn, error) {
	var dialOpts []grpc.DialOption
	if insecure {
		dialOpts = append(dialOpts, grpc.WithTransportCredentials(grpcinsecure.NewCredentials()))
	} else {
		tlsCfg := &tls.Config{MinVersion: tls.VersionTLS13}
		if certFile != "" && keyFile != "" {
			cert, err := tls.LoadX509KeyPair(certFile, keyFile)
			if err != nil {
				return nil, fmt.Errorf("loading client cert %s: %w", certFile, err)
			}
			tlsCfg.Certificates = []tls.Certificate{cert}
		}
		if caFile != "" {
			ca, err := os.ReadFile(caFile)
			if err != nil {
				return nil, fmt.Errorf("reading CA %s: %w", caFile, err)
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(ca) {
				return nil, fmt.Errorf("CA file %s: no PEM certs found", caFile)
			}
			tlsCfg.RootCAs = pool
		}
		dialOpts = append(dialOpts, grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)))
	}

	if apiKey != "" {
		dialOpts = append(dialOpts, grpc.WithPerRPCCredentials(apiKeyCredentials{key: apiKey, insecure: insecure}))
	}

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

func fetchRemoteConfig(conn *grpc.ClientConn) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client := pb.NewControlServiceClient(conn)
	resp, err := client.GetConfig(ctx, &pb.GetConfigRequest{})
	if err != nil {
		return nil, fmt.Errorf("fetching config: %w", err)
	}
	return resp.GetConfigYaml(), nil
}

func copyCertFile(src, home, name string) string {
	data, err := os.ReadFile(src)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading %s: %v\n", src, err)
		os.Exit(1)
	}
	dest := filepath.Join(home, name)
	if err := os.MkdirAll(home, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "error creating %s: %v\n", home, err)
		os.Exit(1)
	}
	if err := os.WriteFile(dest, data, 0600); err != nil {
		fmt.Fprintf(os.Stderr, "error writing %s: %v\n", dest, err)
		os.Exit(1)
	}
	return dest
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
	// 0600: config may contain API key and connection credentials.
	return os.WriteFile(path, data, 0600)
}
