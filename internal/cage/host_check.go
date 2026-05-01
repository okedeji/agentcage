package cage

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/go-logr/logr"
)

// CheckBaseRootfs verifies that the base ext4 image used to assemble cage
// rootfs exists, is readable, and is non-empty. Cheap startup check that
// catches a missing or zero-byte image before the first cage tries to
// provision and fails with an opaque cp error.
func CheckBaseRootfs(path string) string {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "base rootfs not present"
		}
		return fmt.Sprintf("base rootfs stat: %v", err)
	}
	if info.IsDir() {
		return fmt.Sprintf("%s is a directory, not a file", path)
	}
	if info.Size() == 0 {
		return fmt.Sprintf("%s is empty (0 bytes)", path)
	}
	f, err := os.Open(path)
	if err != nil {
		return fmt.Sprintf("base rootfs not readable: %v", err)
	}
	_ = f.Close()
	return ""
}

// CheckFalcoSocket verifies that the given path is a Unix socket Falco is
// actively listening on. Returns an empty string on success or a
// human-readable reason on failure.
func CheckFalcoSocket(ctx context.Context, socketPath string) string {
	info, err := os.Stat(socketPath)
	if err != nil {
		if os.IsNotExist(err) {
			return "socket not present"
		}
		return fmt.Sprintf("socket stat: %v", err)
	}
	if info.Mode()&os.ModeSocket == 0 {
		return fmt.Sprintf("%s is not a unix socket", socketPath)
	}

	dialer := net.Dialer{Timeout: 2 * time.Second}
	conn, err := dialer.DialContext(ctx, "unix", socketPath)
	if err != nil {
		return fmt.Sprintf("socket not accepting connections: %v", err)
	}
	_ = conn.Close()
	return ""
}

// CheckSpireSocket verifies that the given path is a Unix socket the
// SPIRE agent is listening on. Same pattern as CheckFalcoSocket.
func CheckSpireSocket(ctx context.Context, socketPath string) string {
	info, err := os.Stat(socketPath)
	if err != nil {
		if os.IsNotExist(err) {
			return "socket not present"
		}
		return fmt.Sprintf("socket stat: %v", err)
	}
	if info.Mode()&os.ModeSocket == 0 {
		return fmt.Sprintf("%s is not a unix socket", socketPath)
	}

	dialer := net.Dialer{Timeout: 2 * time.Second}
	conn, err := dialer.DialContext(ctx, "unix", socketPath)
	if err != nil {
		return fmt.Sprintf("socket not accepting connections: %v", err)
	}
	_ = conn.Close()
	return ""
}

// CheckNomadHealth verifies that the Nomad HTTP API is reachable at
// the given address. Returns an empty string on success or a reason.
func CheckNomadHealth(ctx context.Context, addr string) string {
	healthURL := addr + "/v1/agent/health"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, healthURL, nil)
	if err != nil {
		return fmt.Sprintf("invalid nomad address: %v", err)
	}
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Sprintf("nomad not reachable at %s: %v", addr, err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode >= 500 {
		return fmt.Sprintf("nomad returned %d at %s", resp.StatusCode, addr)
	}
	return ""
}

// HostRuntimeConfig is the orchestrator-side input to BuildProvisioner:
// resolved binary paths and the operator's opt-in for unisolated mode.
type HostRuntimeConfig struct {
	FirecrackerBin  string
	KernelPath      string
	AllowUnisolated bool
	CageInitBin     string
	SidecarDir      string
}

// BuildProvisioner constructs the VM provisioner used by the cage
// activity layer. It runs pre-flight checks against the host so
// misconfigurations are caught at startup rather than the first cage
// provision. Returns the provisioner and whether cages will be
// kernel-isolated.
//
// If Firecracker prerequisites are not met, AllowUnisolated=true
// falls back to SubprocessProvisioner with a loud warning.
// AllowUnisolated=false returns an error so the orchestrator refuses
// to start, preventing exploit code from running directly on the host.
func BuildProvisioner(ctx context.Context, cfg HostRuntimeConfig, log logr.Logger) (VMProvisioner, bool, error) {
	if reason := checkFirecrackerHost(cfg.FirecrackerBin, cfg.KernelPath); reason != "" {
		if !cfg.AllowUnisolated {
			return nil, false, fmt.Errorf("firecracker not usable (%s); set cage_runtime.allow_unisolated=true to run without microVM isolation", reason)
		}
		log.Info("WARNING: cage isolation disabled, running agents as subprocesses",
			"reason", reason, "cage_init", cfg.CageInitBin, "sidecar_dir", cfg.SidecarDir)
		return NewSubprocessProvisioner(cfg.CageInitBin, cfg.SidecarDir), false, nil
	}

	if version, err := firecrackerVersion(ctx, cfg.FirecrackerBin); err == nil {
		log.Info("firecracker binary OK", "bin", cfg.FirecrackerBin, "version", version, "kernel", cfg.KernelPath)
	} else {
		log.Info("firecracker binary OK (version probe failed)", "bin", cfg.FirecrackerBin, "kernel", cfg.KernelPath, "error", err.Error())
	}

	provisioner := NewFirecrackerProvisioner(FirecrackerConfig{
		BinPath:    cfg.FirecrackerBin,
		KernelPath: cfg.KernelPath,
	}, log)

	if err := provisioner.SweepStale(ctx); err != nil {
		log.Error(err, "sweeping stale firecracker state, continuing")
	}

	return provisioner, true, nil
}

// checkFirecrackerHost verifies that this host can run Firecracker microVMs.
// Returns an empty string on success or a human-readable reason on failure.
func checkFirecrackerHost(firecrackerBin, kernelBin string) string {
	// 1. KVM device must exist AND be openable by this process.
	//    Existence alone isn't enough; the orchestrator user has to
	//    be in the kvm group (or root) for ioctls to succeed.
	f, err := os.OpenFile("/dev/kvm", os.O_RDWR, 0)
	if err != nil {
		if os.IsNotExist(err) {
			return "/dev/kvm not present"
		}
		return fmt.Sprintf("/dev/kvm not openable: %v", err)
	}
	_ = f.Close()

	// 2. Firecracker binary must exist and be executable.
	info, err := os.Stat(firecrackerBin)
	if err != nil {
		return fmt.Sprintf("firecracker binary %s: %v", firecrackerBin, err)
	}
	if info.Mode()&0111 == 0 {
		return fmt.Sprintf("firecracker binary %s is not executable", firecrackerBin)
	}

	// 3. Kernel image must exist and be readable.
	if _, err := os.Stat(kernelBin); err != nil {
		return fmt.Sprintf("kernel image %s: %v", kernelBin, err)
	}

	return ""
}

// firecrackerVersion runs `firecracker --version` and returns the
// trimmed first line. Logging only; a probe failure is not fatal.
func firecrackerVersion(ctx context.Context, bin string) (string, error) {
	out, err := exec.CommandContext(ctx, bin, "--version").Output()
	if err != nil {
		return "", err
	}
	line := strings.TrimSpace(strings.SplitN(string(out), "\n", 2)[0])
	return line, nil
}
