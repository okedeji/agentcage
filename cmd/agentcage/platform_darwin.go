//go:build darwin

package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	pb "github.com/okedeji/agentcage/api/proto"
	"github.com/okedeji/agentcage/internal/vm"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func platformInit(args []string) {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	configFile := fs.String("config", "", "path to config YAML override file")
	grpcAddr := fs.String("grpc-addr", "", "ignored on macOS")
	logFormat := fs.String("log-format", "", "ignored on macOS")
	_ = fs.Parse(args)

	if *grpcAddr != "" {
		fmt.Fprintln(os.Stderr, "warning: --grpc-addr is ignored on macOS (proxy always listens on :9090)")
	}
	if *logFormat != "" {
		fmt.Fprintln(os.Stderr, "warning: --log-format is ignored on macOS (VM uses its own log config)")
	}

	// Resolve agentcage home for VirtioFS share
	home := os.Getenv("AGENTCAGE_HOME")
	if home == "" {
		userHome, err := os.UserHomeDir()
		if err != nil {
			fmt.Fprintf(os.Stderr, "agentcage init: resolving home: %v\n", err)
			os.Exit(1)
		}
		home = userHome + "/.agentcage"
	}
	if err := os.MkdirAll(home, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "agentcage init: creating home: %v\n", err)
		os.Exit(1)
	}

	// Bail out if another instance is already running
	pidFile := filepath.Join(home, "run", "agentcage.pid")
	if isProcessRunning(pidFile) {
		fmt.Fprintln(os.Stderr, "agentcage is already running. Run 'agentcage stop' first.")
		os.Exit(1)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	fmt.Printf("Initializing agentcage v%s (macOS — booting Linux VM)...\n\n", version)

	// Download VM assets
	fmt.Println("Downloading VM assets...")
	if err := vm.EnsureAssets(ctx, version); err != nil {
		fmt.Fprintf(os.Stderr, "agentcage init: %v\n", err)
		os.Exit(1)
	}

	// Copy config override into shared directory so the VM can read it
	if *configFile != "" {
		data, err := os.ReadFile(*configFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "agentcage init: reading config %s: %v\n", *configFile, err)
			os.Exit(1)
		}
		dest := home + "/config.yaml"
		if err := os.WriteFile(dest, data, 0644); err != nil {
			fmt.Fprintf(os.Stderr, "agentcage init: writing config to shared dir: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Config copied to %s (shared with VM)\n", dest)
	}

	// Boot VM
	fmt.Println("Booting Linux VM...")
	cfg := vm.DefaultConfig(home)
	machine, err := vm.Boot(ctx, cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentcage init: booting VM: %v\n", err)
		os.Exit(1)
	}

	// fatalf shuts down the VM and cleans up the PID file before exiting.
	// os.Exit skips defers, so early-exit paths must call this directly.
	fatalf := func(format string, args ...any) {
		fmt.Fprintf(os.Stderr, format, args...)
		_ = os.Remove(pidFile)
		_ = machine.Shutdown(context.Background())
		os.Exit(1)
	}

	// Write PID file so `agentcage stop` can find the host process
	_ = os.MkdirAll(filepath.Dir(pidFile), 0755)
	_ = os.WriteFile(pidFile, []byte(fmt.Sprintf("%d", os.Getpid())), 0644)
	defer func() { _ = os.Remove(pidFile) }()

	// Forward localhost ports to the VM so CLI commands and users
	// connect to localhost without knowing the VM's DHCP-assigned IP.
	vmIP := machine.IP()
	if vmIP == "" {
		fatalf("agentcage init: VM booted but reported no IP address\n")
	}

	// Bind proxy listeners eagerly so we fail fast on port conflicts
	// instead of timing out in waitForGRPCReady with a misleading error.
	grpcLn, err := net.Listen("tcp", "127.0.0.1:9090")
	if err != nil {
		fatalf("agentcage init: port 9090 already in use — is another agentcage running?\n  Check: lsof -i :9090\n")
	}
	pgLn, err := net.Listen("tcp", "127.0.0.1:15432")
	if err != nil {
		_ = grpcLn.Close()
		fatalf("agentcage init: port 15432 already in use\n  Check: lsof -i :15432\n")
	}

	go func() {
		if err := tcpProxyFromListener(ctx, grpcLn, net.JoinHostPort(vmIP, "9090")); err != nil && ctx.Err() == nil {
			fmt.Fprintf(os.Stderr, "gRPC proxy failed: %v\n", err)
			cancel()
		}
	}()
	go func() {
		if err := tcpProxyFromListener(ctx, pgLn, net.JoinHostPort(vmIP, "15432")); err != nil && ctx.Err() == nil {
			fmt.Fprintf(os.Stderr, "Postgres proxy failed: %v\n", err)
			cancel()
		}
	}()

	// Wait for gRPC server inside VM to be fully ready (not just TCP-open)
	fmt.Println("Waiting for services inside VM to be ready...")
	readyCtx, readyCancel := context.WithTimeout(ctx, 120*time.Second)
	defer readyCancel()
	if err := waitForGRPCReady(readyCtx, machine.GRPCAddr()); err != nil {
		if ctx.Err() != nil {
			fatalf("agentcage init: proxy failed during startup — check port conflicts above\n")
		}
		fatalf("agentcage init: VM services did not become ready: %v\n", err)
	}

	fmt.Printf("\nagentcage ready (running inside Linux VM).\n")
	fmt.Printf("  gRPC:     localhost:9090\n")
	fmt.Printf("  Postgres: localhost:15432\n")
	fmt.Printf("  VM:       Apple Virtualization.framework (%s)\n", runtime.GOARCH)
	fmt.Printf("  Data:     %s\n\n", home)
	fmt.Println("Press Ctrl+C to stop.")

	// Wait for shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	select {
	case <-sigCh:
	case <-ctx.Done():
	}

	fmt.Println("\nShutting down...")

	fmt.Println("Stopping services inside VM...")
	stopCtx, stopCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer stopCancel()

	conn, err := grpc.NewClient(machine.GRPCAddr(),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err == nil {
		client := pb.NewControlServiceClient(conn)
		_, _ = client.Stop(stopCtx, &pb.StopRequest{})
		_ = conn.Close()
	}

	fmt.Println("Shutting down VM...")
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer shutdownCancel()
	if err := machine.Shutdown(shutdownCtx); err != nil {
		fmt.Fprintf(os.Stderr, "warning: VM shutdown error: %v\n", err)
	}

	fmt.Println("agentcage stopped.")
}

func platformStop(_ []string) {
	conn, err := grpc.NewClient("localhost:9090",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		fmt.Fprintln(os.Stderr, "agentcage is not running.")
		os.Exit(1)
	}
	defer func() { _ = conn.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client := pb.NewControlServiceClient(conn)
	pingResp, err := client.Ping(ctx, &pb.PingRequest{})
	if err != nil {
		fmt.Fprintln(os.Stderr, "agentcage is not running.")
		os.Exit(1)
	}
	if pingResp.GetStatus() != "running" {
		fmt.Fprintf(os.Stderr, "service on :9090 is not agentcage (status=%s).\n", pingResp.GetStatus())
		os.Exit(1)
	}

	if _, err := client.Stop(ctx, &pb.StopRequest{}); err != nil {
		fmt.Fprintf(os.Stderr, "error stopping agentcage: %v\n", err)
		os.Exit(1)
	}

	// Wait for gRPC to become unreachable (confirms actual shutdown)
	fmt.Println("Waiting for shutdown...")
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		checkCtx, checkCancel := context.WithTimeout(context.Background(), 1*time.Second)
		_, pingErr := client.Ping(checkCtx, &pb.PingRequest{})
		checkCancel()
		if pingErr != nil {
			fmt.Println("agentcage stopped.")
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	fmt.Fprintln(os.Stderr, "warning: agentcage may still be shutting down (gRPC still reachable after 15s).")
}

func isProxyCommand(cmd string) bool {
	switch cmd {
	case "run", "test", "status", "findings", "report",
		"interventions", "resolve", "fleet":
		return true
	}
	return false
}

// tcpProxyFromListener proxies connections from an already-bound listener
// to targetAddr. It closes the listener when ctx is cancelled.
func tcpProxyFromListener(ctx context.Context, ln net.Listener, targetAddr string) error {
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	for {
		clientConn, err := ln.Accept()
		if err != nil {
			return err
		}
		go func() {
			defer func() { _ = clientConn.Close() }()

			targetConn, err := net.DialTimeout("tcp", targetAddr, 5*time.Second)
			if err != nil {
				return
			}
			defer func() { _ = targetConn.Close() }()

			done := make(chan struct{})
			go func() {
				_, _ = io.Copy(targetConn, clientConn)
				close(done)
			}()
			_, _ = io.Copy(clientConn, targetConn)
			<-done
		}()
	}
}

func waitForGRPCReady(ctx context.Context, addr string) error {
	start := time.Now()
	lastReport := start
	for {
		conn, err := grpc.NewClient(addr,
			grpc.WithTransportCredentials(insecure.NewCredentials()),
		)
		if err == nil {
			pingCtx, pingCancel := context.WithTimeout(ctx, 2*time.Second)
			client := pb.NewControlServiceClient(conn)
			_, pingErr := client.Ping(pingCtx, &pb.PingRequest{})
			pingCancel()
			_ = conn.Close()
			if pingErr == nil {
				return nil
			}
		}

		if time.Since(lastReport) >= 10*time.Second {
			fmt.Printf("  Still waiting for services... (%ds elapsed)\n", int(time.Since(start).Seconds()))
			lastReport = time.Now()
		}

		select {
		case <-ctx.Done():
			return fmt.Errorf("timed out waiting for gRPC readiness at %s", addr)
		case <-time.After(2 * time.Second):
		}
	}
}
