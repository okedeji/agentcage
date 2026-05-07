package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/go-logr/logr"
	"go.temporal.io/sdk/worker"
	"google.golang.org/grpc"

	"github.com/okedeji/agentcage/internal/alert"
	"github.com/okedeji/agentcage/internal/embedded"
	"github.com/okedeji/agentcage/internal/ui"
)

// detachProcess re-execs the current binary with the same args minus
// --detach, redirects output to a log file, and exits. The child
// runs in the background as a daemon.
func detachProcess(args []string) {
	logPath := filepath.Join(embedded.LogDir(), "agentcage.out")
	_ = os.MkdirAll(filepath.Dir(logPath), 0755)

	outFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		ui.Fail("creating detach log: %v", err)
		os.Exit(1)
	}

	// Remove --detach from args so the child runs in foreground.
	var childArgs []string
	for _, a := range args {
		if a != "--detach" {
			childArgs = append(childArgs, a)
		}
	}

	exe, err := os.Executable()
	if err != nil {
		ui.Fail("resolving executable path: %v", err)
		os.Exit(1)
	}

	proc, err := os.StartProcess(exe, append([]string{exe}, childArgs...), &os.ProcAttr{
		Dir:   ".",
		Env:   os.Environ(),
		Files: []*os.File{devNull(), outFile, outFile},
		Sys:   &syscall.SysProcAttr{Setsid: true},
	})
	if err != nil {
		ui.Fail("starting background process: %v", err)
		os.Exit(1)
	}

	pid := proc.Pid
	_ = proc.Release()

	ui.Header(version)

	// Wait for gRPC to become reachable before reporting success.
	// This ensures `agentcage stop` works immediately after detach returns.
	progress := ui.Progress("Starting")
	readyCtx, readyCancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer readyCancel()
	addr := "127.0.0.1:9090"
	for {
		conn, err := net.DialTimeout("tcp", addr, 1*time.Second)
		if err == nil {
			_ = conn.Close()
			break
		}
		if err := syscall.Kill(pid, 0); err != nil {
			progress.Fail()
			ui.Fail("agentcage exited before becoming ready. Check: %s", logPath)
			os.Exit(1)
		}
		select {
		case <-readyCtx.Done():
			progress.Fail()
			ui.Fail("timed out waiting for agentcage to start. Check: %s", logPath)
			os.Exit(1)
		case <-time.After(1 * time.Second):
		}
	}

	progress.Done()
	fmt.Println()
	ui.Info("gRPC", addr)
	ui.Info("Postgres", "localhost:15432")
	ui.Info("Logs", "agentcage logs orchestrator")
	ui.Info("PID", fmt.Sprintf("%d", pid))
	ui.Info("Stop", "agentcage stop")
	os.Exit(0)
}

func devNull() *os.File {
	f, _ := os.Open(os.DevNull)
	return f
}

// Every shutdown step is bounded so a wedged component can't trap
// the operator. The overall deadline catches whatever we missed.
const (
	gracefulShutdownDeadline = 15 * time.Second
	embeddedStopDeadline     = 30 * time.Second
	identityStopDeadline     = 10 * time.Second
	overallShutdownDeadline  = 90 * time.Second
)

// waitForShutdown blocks until ctx is cancelled or the operator sends
// SIGINT/SIGTERM. SIGHUP triggers a scoped reload (today, just the
// file-TLS cert) and does not exit.
//
// Buffer 2 so a HUP arriving just before a TERM doesn't drop the TERM.
func waitForShutdown(
	ctx context.Context,
	log logr.Logger,
) chan os.Signal {
	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-sigCh:
		log.Info("received signal, shutting down", "signal", sig.String())
	case <-ctx.Done():
		log.Info("internal cancel, shutting down")
	}
	return sigCh
}

type shutdownDeps struct {
	grpcServer       *grpc.Server
	cageWorker       worker.Worker
	assessmentWorker worker.Worker
	identityCleanup  func()
	alertDispatcher  *alert.Dispatcher
	embeddedMgr      *embedded.Manager
}

// Workflows mid-flight when workers stop are durable and resume
// on next start. A second signal force-exits if the graceful path
// wedges.
func shutdownSequence(
	cancel context.CancelFunc,
	deps shutdownDeps,
	sigCh chan os.Signal,
	log logr.Logger,
) {
	if sigCh != nil {
		go forceExitOnSecondSignal(sigCh)
	}

	fmt.Println()
	stopProgress := ui.Progress("Stopping")

	// Hard deadline on the whole sequence. Every step is bounded
	// individually, but a future addition could still hang. Force-exit
	// beats leaving kill -9 as the operator's only option.
	shutdownTimer := time.AfterFunc(overallShutdownDeadline, func() {
		fmt.Fprintln(os.Stderr, "shutdown exceeded 90s, forcing exit")
		os.Exit(2)
	})
	defer shutdownTimer.Stop()

	cancel()

	stopGRPCBounded(deps.grpcServer, log)
	stopWorkersParallel(deps.cageWorker, deps.assessmentWorker)

	// Revokes have to run before embedded Vault stops, otherwise the
	// calls fail and cage credentials outlive the orchestrator.
	stopIdentityBounded(deps.identityCleanup, log)

	deps.alertDispatcher.Close()

	stopEmbeddedBounded(deps.embeddedMgr, log)

	stopProgress.Done()
}

// SIGHUP is ignored here because operators occasionally send it by
// accident during shutdown.
func forceExitOnSecondSignal(sigCh chan os.Signal) {
	for sig := range sigCh {
		if sig == syscall.SIGHUP {
			continue
		}
		fmt.Fprintln(os.Stderr, "second signal received during shutdown, forcing exit")
		os.Exit(1)
	}
}

// 15s. An RPC that hasn't finished by then is stuck.
func stopGRPCBounded(server *grpc.Server, log logr.Logger) {
	stopped := make(chan struct{})
	go func() {
		server.GracefulStop()
		close(stopped)
	}()
	select {
	case <-stopped:
	case <-time.After(gracefulShutdownDeadline):
		log.Info("gRPC graceful stop timed out, forcing close")
		server.Stop()
	}
}

// Each Stop() blocks up to 30s draining activities. The two are
// independent, so sequential would double worst-case shutdown.
func stopWorkersParallel(cageWorker, assessmentWorker worker.Worker) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		cageWorker.Stop()
	}()
	go func() {
		defer wg.Done()
		assessmentWorker.Stop()
	}()
	wg.Wait()
}

// A wedged Vault would otherwise block the revoke path forever.
func stopIdentityBounded(cleanup func(), log logr.Logger) {
	if cleanup == nil {
		return
	}
	done := make(chan struct{})
	go func() {
		cleanup()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(identityStopDeadline):
		log.Info("identity cleanup timed out, abandoning revoke calls")
	}
}

func stopEmbeddedBounded(mgr *embedded.Manager, log logr.Logger) {
	stopCtx, stopCancel := context.WithTimeout(context.Background(), embeddedStopDeadline)
	defer stopCancel()
	if err := mgr.Stop(stopCtx); err != nil {
		log.Error(err, "error stopping embedded services")
	}
}

// writePIDFile creates path with O_EXCL so a concurrent agentcage
// can't clobber it. If the file already exists we check the PID:
// live means another orchestrator is running and we refuse to start;
// dead means the previous run crashed and we reclaim the file.
func writePIDFile(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("creating pid dir: %w", err)
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
	if err == nil {
		defer func() { _ = f.Close() }()
		if _, werr := fmt.Fprintf(f, "%d", os.Getpid()); werr != nil {
			_ = os.Remove(path)
			return fmt.Errorf("writing pid: %w", werr)
		}
		return nil
	}
	if !errors.Is(err, fs.ErrExist) {
		return fmt.Errorf("creating pid file: %w", err)
	}

	// File exists. Check whether the PID is alive.
	existing, readErr := os.ReadFile(path)
	if readErr != nil {
		return fmt.Errorf("reading existing pid file %s: %w", path, readErr)
	}
	pid, parseErr := strconv.Atoi(strings.TrimSpace(string(existing)))
	if parseErr != nil {
		// Garbage in the file. Reclaim.
		if rmErr := os.Remove(path); rmErr != nil {
			return fmt.Errorf("removing corrupt pid file: %w", rmErr)
		}
		return writePIDFile(path)
	}
	proc, _ := os.FindProcess(pid) // never errors on unix
	// signal 0 probes liveness without affecting the process.
	if err := proc.Signal(syscall.Signal(0)); err == nil {
		return fmt.Errorf("another agentcage appears to be running (pid %d). If not, remove %s and retry", pid, path)
	}
	// Stale from a previous crash. Reclaim.
	if rmErr := os.Remove(path); rmErr != nil {
		return fmt.Errorf("removing stale pid file: %w", rmErr)
	}
	return writePIDFile(path)
}
