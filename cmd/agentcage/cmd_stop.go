package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/okedeji/agentcage/internal/embedded"
)

var _ = cmdStop

func isProcessRunning(pidFile string) bool {
	data, err := os.ReadFile(pidFile)
	if err != nil {
		return false
	}
	var pid int
	if _, err := fmt.Sscanf(strings.TrimSpace(string(data)), "%d", &pid); err != nil {
		return false
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	return proc.Signal(syscall.Signal(0)) == nil
}

// Embedded services write their own PID files. If the orchestrator
// was SIGKILLed those children are still running with no parent to
// stop them.
func killOrphanedServices() {
	runDir := embedded.RunDir()
	entries, err := os.ReadDir(runDir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".pid") || e.Name() == "agentcage.pid" {
			continue
		}
		pidPath := filepath.Join(runDir, e.Name())
		data, err := os.ReadFile(pidPath)
		if err != nil {
			continue
		}
		var pid int
		if _, err := fmt.Sscanf(strings.TrimSpace(string(data)), "%d", &pid); err != nil {
			continue
		}
		proc, err := os.FindProcess(pid)
		if err != nil {
			_ = os.Remove(pidPath)
			continue
		}
		if err := proc.Signal(syscall.Signal(0)); err != nil {
			_ = os.Remove(pidPath)
			continue
		}
		fmt.Fprintf(os.Stderr, "  killing orphaned service %s (pid %d)\n", strings.TrimSuffix(e.Name(), ".pid"), pid)
		_ = proc.Signal(syscall.SIGKILL)
		_ = os.Remove(pidPath)
	}
}

func cmdStop(_ []string) {
	pidFile := embedded.RunDir() + "/agentcage.pid"
	data, err := os.ReadFile(pidFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "agentcage is not running.")
		os.Exit(1)
	}

	var pid int
	if _, err := fmt.Sscanf(string(data), "%d", &pid); err != nil {
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

	if err := proc.Signal(syscall.SIGTERM); err != nil {
		fmt.Fprintf(os.Stderr, "failed to stop agentcage (pid %d): %v\n", pid, err)
		os.Exit(1)
	}

	fmt.Printf("Stopping agentcage (pid %d)...\n", pid)

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
	if err := proc.Signal(syscall.SIGKILL); err != nil {
		fmt.Fprintf(os.Stderr, "failed to kill agentcage (pid %d): %v\n", pid, err)
		os.Exit(1)
	}
	_ = os.Remove(pidFile)
	killOrphanedServices()
	fmt.Println("agentcage killed.")
}
