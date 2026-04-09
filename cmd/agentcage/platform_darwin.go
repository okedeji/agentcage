//go:build darwin

package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	pb "github.com/okedeji/agentcage/api/proto"
	"github.com/okedeji/agentcage/internal/embedded"
	agentgrpc "github.com/okedeji/agentcage/internal/grpc"
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

	// VM reads from this directory via VirtioFS, so it has to exist
	// before we boot.
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

	pidFile := filepath.Join(home, "run", "agentcage.pid")
	if isProcessRunning(pidFile) {
		fmt.Fprintln(os.Stderr, "agentcage is already running. Run 'agentcage stop' first.")
		os.Exit(1)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	fmt.Printf("Initializing agentcage v%s (macOS, booting Linux VM)...\n\n", version)

	fmt.Println("Downloading VM assets...")
	if err := vm.EnsureAssets(ctx, version); err != nil {
		fmt.Fprintf(os.Stderr, "agentcage init: %v\n", err)
		os.Exit(1)
	}

	// VM can't read host paths, so the config has to land in the
	// shared directory before boot.
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

	fmt.Println("Booting Linux VM...")
	cfg := vm.DefaultConfig(home)
	machine, err := vm.Boot(ctx, cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentcage init: booting VM: %v\n", err)
		os.Exit(1)
	}

	// os.Exit skips defers, so any error path that needs to tear the
	// VM down and remove the PID file has to do it explicitly here.
	fatalf := func(format string, args ...any) {
		fmt.Fprintf(os.Stderr, format, args...)
		_ = os.Remove(pidFile)
		_ = machine.Shutdown(context.Background())
		os.Exit(1)
	}

	// `agentcage stop` reads this to find the host process.
	_ = os.MkdirAll(filepath.Dir(pidFile), 0755)
	_ = os.WriteFile(pidFile, []byte(fmt.Sprintf("%d", os.Getpid())), 0644)
	defer func() { _ = os.Remove(pidFile) }()

	// VM gets a DHCP IP that changes between boots, so we present a
	// stable localhost interface for the CLI and operators.
	vmIP := machine.IP()
	if vmIP == "" {
		fatalf("agentcage init: VM booted but reported no IP address\n")
	}

	// Bind eagerly so a port conflict fails fast with a clear error
	// instead of timing out in waitForGRPCReady with a misleading one.
	grpcLn, err := net.Listen("tcp", "127.0.0.1:9090")
	if err != nil {
		fatalf("agentcage init: port 9090 already in use. Is another agentcage running?\n  Check: lsof -i :9090\n")
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

	// Real RPC, not a TCP connect check. The TCP socket opens long
	// before the gRPC server starts dispatching.
	fmt.Println("Waiting for services inside VM to be ready...")
	readyCtx, readyCancel := context.WithTimeout(ctx, 120*time.Second)
	defer readyCancel()
	if err := agentgrpc.WaitForReady(readyCtx, machine.GRPCAddr()); err != nil {
		if ctx.Err() != nil {
			fatalf("agentcage init: proxy failed during startup, check port conflicts above\n")
		}
		fatalf("agentcage init: VM services did not become ready: %v\n", err)
	}

	fmt.Printf("\nagentcage ready (running inside Linux VM).\n")
	fmt.Printf("  gRPC:     localhost:9090\n")
	fmt.Printf("  Postgres: localhost:15432\n")
	fmt.Printf("  VM:       Apple Virtualization.framework (%s)\n", runtime.GOARCH)
	fmt.Printf("  Data:     %s\n\n", home)
	fmt.Println("Press Ctrl+C to stop.")

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
	pidFile := filepath.Join(embedded.RunDir(), "agentcage.pid")

	if stopViaGRPC() {
		_ = os.Remove(pidFile)
		return
	}

	fmt.Println("gRPC unreachable, falling back to process signal...")
	stopViaPID(pidFile)
}

// Returns true only once the gRPC server is confirmed unreachable.
func stopViaGRPC() bool {
	conn, err := grpc.NewClient("localhost:9090",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return false
	}
	defer func() { _ = conn.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client := pb.NewControlServiceClient(conn)
	pingResp, err := client.Ping(ctx, &pb.PingRequest{})
	if err != nil {
		return false
	}
	if pingResp.GetStatus() != "running" {
		fmt.Fprintf(os.Stderr, "service on :9090 is not agentcage (status=%s).\n", pingResp.GetStatus())
		os.Exit(1)
	}

	fmt.Println("Stopping agentcage...")
	if _, err := client.Stop(ctx, &pb.StopRequest{}); err != nil {
		fmt.Fprintf(os.Stderr, "error sending stop: %v\n", err)
		return false
	}

	fmt.Println("Waiting for shutdown...")
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		checkCtx, checkCancel := context.WithTimeout(context.Background(), 1*time.Second)
		_, pingErr := client.Ping(checkCtx, &pb.PingRequest{})
		checkCancel()
		if pingErr != nil {
			fmt.Println("agentcage stopped.")
			return true
		}
		time.Sleep(500 * time.Millisecond)
	}

	fmt.Fprintln(os.Stderr, "gRPC still reachable after 15s.")
	return false
}

func stopViaPID(pidFile string) {
	data, err := os.ReadFile(pidFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "agentcage is not running.")
		os.Exit(1)
	}

	var pid int
	if _, err := fmt.Sscanf(strings.TrimSpace(string(data)), "%d", &pid); err != nil {
		fmt.Fprintf(os.Stderr, "invalid PID file: %v\n", err)
		os.Exit(1)
	}

	proc, err := os.FindProcess(pid)
	if err != nil {
		fmt.Fprintf(os.Stderr, "process %d not found: %v\n", pid, err)
		_ = os.Remove(pidFile)
		os.Exit(1)
	}

	if err := proc.Signal(syscall.Signal(0)); err != nil {
		fmt.Fprintln(os.Stderr, "agentcage is not running (stale PID file).")
		_ = os.Remove(pidFile)
		os.Exit(1)
	}

	fmt.Printf("Stopping agentcage (pid %d)...\n", pid)
	if err := proc.Signal(syscall.SIGTERM); err != nil {
		fmt.Fprintf(os.Stderr, "failed to stop agentcage (pid %d): %v\n", pid, err)
		os.Exit(1)
	}

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if err := proc.Signal(syscall.Signal(0)); err != nil {
			fmt.Println("agentcage stopped.")
			_ = os.Remove(pidFile)
			return
		}
		time.Sleep(250 * time.Millisecond)
	}

	fmt.Fprintf(os.Stderr, "agentcage did not stop within 10s, sending SIGKILL...\n")
	_ = proc.Signal(syscall.SIGKILL)
	_ = os.Remove(pidFile)
	fmt.Println("agentcage killed.")
}

func isProxyCommand(cmd string) bool {
	switch cmd {
	case "test", "status", "findings", "report",
		"interventions", "resolve", "fleet":
		return true
	}
	return false
}

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

