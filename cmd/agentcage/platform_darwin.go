//go:build darwin

package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	pb "github.com/okedeji/agentcage/api/proto"
	"github.com/okedeji/agentcage/internal/config"
	"github.com/okedeji/agentcage/internal/embedded"
	agentgrpc "github.com/okedeji/agentcage/internal/grpc"
	"github.com/okedeji/agentcage/internal/ui"
	"github.com/okedeji/agentcage/internal/vm"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func platformInit(args []string) {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	configFile := fs.String("config", "", "path to config YAML override file")
	secretsFile := fs.String("secrets", "", "path to secrets file (KEY=VALUE lines, seeded into Vault on first boot)")
	grpcAddr := fs.String("grpc-addr", "127.0.0.1:9090", "host-side gRPC proxy address")
	detach := fs.Bool("detach", false, "run in background")
	_ = fs.Parse(args)

	if *detach {
		detachProcess(append([]string{"init"}, args...))
	}

	// VM reads from this directory via VirtioFS, so it has to exist
	// before we boot.
	home := config.HomeDir()
	if err := os.MkdirAll(home, 0755); err != nil {
		ui.Fail("creating home: %v", err)
		os.Exit(1)
	}

	pidFile := filepath.Join(home, "run", "agentcage.pid")
	if isProcessRunning(pidFile) {
		ui.Fail("agentcage is already running. Run 'agentcage stop' first.")
		os.Exit(1)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ui.Banner(version, "")

	if err := vm.EnsureAssets(ctx, version); err != nil {
		ui.Fail("%v", err)
		os.Exit(1)
	}

	// VM can't read host paths, so the config has to land in the
	// shared directory before boot.
	if *configFile != "" {
		data, err := os.ReadFile(*configFile)
		if err != nil {
			ui.Fail("reading config %s: %v", *configFile, err)
			os.Exit(1)
		}
		dest := home + "/config.yaml"
		if err := os.WriteFile(dest, data, 0600); err != nil {
			ui.Fail("writing config to shared dir: %v", err)
			os.Exit(1)
		}
	}

	if *secretsFile != "" {
		data, err := os.ReadFile(*secretsFile)
		if err != nil {
			ui.Fail("reading secrets %s: %v", *secretsFile, err)
			os.Exit(1)
		}
		dest := home + "/secrets.env"
		if err := os.WriteFile(dest, data, 0600); err != nil {
			ui.Fail("writing secrets to shared dir: %v", err)
			os.Exit(1)
		}
	}

	// VM has no hardware clock and boots to 1970. Write the host
	// time so the init script can set it before TLS connections.
	_ = os.WriteFile(filepath.Join(home, ".vm-clock"),
		[]byte(time.Now().UTC().Format("2006-01-02 15:04:05")), 0644)

	vmCfg := vm.DefaultConfig(home)
	consoleLogPath := filepath.Join(home, "vm-console.log")
	startTime := time.Now()

	// Stream service progress from the VM console to the host
	// terminal. The goroutine tails vm-console.log and forwards
	// progress lines, hiding the VM's own banner and init preamble.
	streamDone := make(chan struct{})
	go streamVMProgress(ctx, consoleLogPath, streamDone)

	machine, err := vm.Boot(ctx, vmCfg)
	if err != nil {
		close(streamDone)
		ui.Fail("failed to start: %v", err)
		os.Exit(1)
	}

	// os.Exit skips defers, so any error path that needs to tear the
	// VM down and remove the PID file has to do it explicitly here.
	fatalf := func(format string, args ...any) {
		close(streamDone)
		ui.Fail(format, args...)
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
		fatalf("services started but reported no network address")
	}

	// Bind eagerly so a port conflict fails fast with a clear error.
	grpcLn, err := net.Listen("tcp", *grpcAddr)
	if err != nil {
		fatalf("port %s already in use. Is another agentcage running?\n  Check: lsof -i :%s", *grpcAddr, portFromAddr(*grpcAddr))
	}
	pgLn, err := net.Listen("tcp", "127.0.0.1:15432")
	if err != nil {
		_ = grpcLn.Close()
		fatalf("port 15432 already in use\n  Check: lsof -i :15432")
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

	readyCtx, readyCancel := context.WithTimeout(ctx, 10*time.Second)
	defer readyCancel()
	if err := agentgrpc.WaitForReady(readyCtx, machine.GRPCAddr()); err != nil {
		fatalf("services did not become ready: %v", err)
	}

	close(streamDone)

	elapsed := time.Since(startTime).Truncate(time.Second)
	ui.ReadyWithElapsed(elapsed)
	ui.Info("gRPC", *grpcAddr)
	ui.Info("Postgres", "localhost:15432")
	ui.Info("Data", home)
	ui.Step("Press Ctrl+C to stop.")

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	select {
	case <-sigCh:
	case <-ctx.Done():
	}

	ui.Shutdown()

	ui.Step("Stopping services")
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

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer shutdownCancel()
	if err := machine.Shutdown(shutdownCtx); err != nil {
		fmt.Fprintf(os.Stderr, "warning: shutdown error: %v\n", err)
	}

	ui.Stopped()
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
	conn, err := grpc.NewClient(config.DefaultGRPCAddr,
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
			ui.Stopped()
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
			ui.Stopped()
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

var ansiRe = regexp.MustCompile(`\x1b\[[0-9;]*m`)

// streamVMProgress tails the VM console log and prints service
// startup progress to the host terminal. Skips the VM's banner
// and init-script preamble. Stops when done is closed.
func streamVMProgress(ctx context.Context, logPath string, done <-chan struct{}) {
	var f *os.File
	for {
		var err error
		f, err = os.Open(logPath)
		if err == nil {
			break
		}
		select {
		case <-done:
			return
		case <-ctx.Done():
			return
		case <-time.After(200 * time.Millisecond):
		}
	}
	defer func() { _ = f.Close() }()

	buf := make([]byte, 0, 4096)
	pastBanner := false

	for {
		select {
		case <-done:
			return
		case <-ctx.Done():
			return
		default:
		}

		tmp := make([]byte, 1024)
		n, _ := f.Read(tmp)
		if n == 0 {
			select {
			case <-done:
				return
			case <-time.After(100 * time.Millisecond):
			}
			continue
		}

		buf = append(buf, tmp[:n]...)

		for {
			idx := bytes.IndexByte(buf, '\n')
			if idx < 0 {
				break
			}
			line := string(buf[:idx])
			buf = buf[idx+1:]

			plain := ansiRe.ReplaceAllString(line, "")

			if !pastBanner {
				if strings.HasPrefix(plain, "  >> ") || strings.HasPrefix(plain, "     Generating") {
					pastBanner = true
				} else {
					continue
				}
			}

			if strings.Contains(plain, "● ready") {
				return
			}

			line = strings.ReplaceAll(line, "/mnt/agentcage/", "")
			line = strings.Replace(line, " on 0.0.0.0:9090", "", 1)

			fmt.Println(line)
		}
	}
}

