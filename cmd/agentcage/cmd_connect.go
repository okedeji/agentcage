package main

import (
	"context"
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
	insecureFlag := fs.Bool("insecure", false, "skip TLS (localhost/dev only)")
	_ = fs.Parse(args)

	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "usage: agentcage connect <address> [--cert <file> --key <file> --ca <file>] [--insecure]")
		fmt.Fprintln(os.Stderr, "\nExamples:")
		fmt.Fprintln(os.Stderr, "  agentcage connect orchestrator.prod:9090 --cert client.crt --key client.key --ca ca.pem")
		fmt.Fprintln(os.Stderr, "  agentcage connect localhost:9090 --insecure")
		os.Exit(1)
	}

	addr := fs.Arg(0)

	if !*insecureFlag && *caFile == "" {
		fmt.Fprintln(os.Stderr, "error: specify --ca <file> for TLS or --insecure for plaintext")
		os.Exit(1)
	}

	if err := pingOrchestrator(addr, *caFile, *insecureFlag); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
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

	if err := writeServerConfig(server); err != nil {
		fmt.Fprintf(os.Stderr, "error saving config: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Connected to %s\n", addr)
	fmt.Printf("Config saved to %s\n", config.DefaultPath())
}

func pingOrchestrator(addr, caFile string, insecure bool) error {
	var creds grpc.DialOption
	if insecure || caFile == "" {
		creds = grpc.WithTransportCredentials(grpcinsecure.NewCredentials())
	} else {
		tc, err := credentials.NewClientTLSFromFile(caFile, "")
		if err != nil {
			return fmt.Errorf("loading CA %s: %w", caFile, err)
		}
		creds = grpc.WithTransportCredentials(tc)
	}

	conn, err := grpc.NewClient(addr, creds)
	if err != nil {
		return fmt.Errorf("connecting to %s: %w", addr, err)
	}
	defer func() { _ = conn.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client := pb.NewControlServiceClient(conn)
	if _, err := client.Ping(ctx, &pb.PingRequest{}); err != nil {
		return fmt.Errorf("orchestrator not reachable at %s: %w", addr, err)
	}
	return nil
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

func writeServerConfig(server config.ServerConfig) error {
	path := config.DefaultPath()

	var cfg config.Config
	if data, err := os.ReadFile(path); err == nil {
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
	return os.WriteFile(path, data, 0644)
}
