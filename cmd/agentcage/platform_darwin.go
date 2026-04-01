//go:build darwin

package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
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
	if runtime.GOOS != "darwin" {
		cmdInit(args)
		return
	}

	if runtime.GOARCH == "amd64" {
		fmt.Println("WARNING: Intel Mac detected. Firecracker cannot create nested microVMs (no KVM).")
		fmt.Println("         SPIRE, Falco, and other services will work. Agent cages will use mock isolation.")
		fmt.Println()
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

	// Boot VM
	fmt.Println("Booting Linux VM...")
	cfg := vm.DefaultConfig(home)
	machine, err := vm.Boot(ctx, cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentcage init: booting VM: %v\n", err)
		os.Exit(1)
	}

	// Start local TCP proxy: localhost:9090 -> VM:9090
	proxyAddr := ":9090"
	go func() {
		if err := tcpProxy(proxyAddr, machine.GRPCAddr()); err != nil {
			fmt.Fprintf(os.Stderr, "gRPC proxy error: %v\n", err)
			cancel()
		}
	}()

	fmt.Printf("\nagentcage ready (running inside Linux VM).\n")
	fmt.Printf("  gRPC:     localhost%s\n", proxyAddr)
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

	// Send graceful stop to VM's agentcage
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

	// Shutdown VM
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer shutdownCancel()
	if err := machine.Shutdown(shutdownCtx); err != nil {
		fmt.Fprintf(os.Stderr, "warning: VM shutdown error: %v\n", err)
	}

	fmt.Println("agentcage stopped.")
}

func platformStop(args []string) {
	conn, err := grpc.NewClient("localhost:9090",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		fmt.Fprintln(os.Stderr, "agentcage is not running.")
		os.Exit(1)
	}
	defer func() { _ = conn.Close() }()

	client := pb.NewControlServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err = client.Stop(ctx, &pb.StopRequest{})
	if err != nil {
		fmt.Fprintf(os.Stderr, "error stopping agentcage: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("agentcage stopped.")
}

func isProxyCommand(cmd string) bool {
	switch cmd {
	case "run", "test", "status", "findings", "report",
		"interventions", "resolve", "fleet", "db", "logs", "audit":
		return true
	}
	return false
}

// tcpProxy listens on listenAddr and proxies connections to targetAddr.
func tcpProxy(listenAddr, targetAddr string) error {
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return fmt.Errorf("listening on %s: %w", listenAddr, err)
	}
	defer func() { _ = ln.Close() }()

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
