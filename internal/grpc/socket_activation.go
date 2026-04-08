package grpc

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"syscall"
)

// systemd socket activation protocol constants. systemd sets these env
// vars on the inherited process and passes pre-bound fds starting at
// fd 3. Protocol documented at sd_listen_fds(3).
const (
	listenPIDEnv = "LISTEN_PID"
	listenFDsEnv = "LISTEN_FDS"

	// systemd's convention: passed fds start at SD_LISTEN_FDS_START.
	systemdListenFDsStart = 3
)

// AcquireListener returns a TCP listener for addr. If systemd socket
// activation is in effect (LISTEN_PID matches our pid and LISTEN_FDS
// >= 1), the first inherited fd is wrapped as a net.Listener and
// returned with activated=true. Otherwise it falls back to
// net.Listen("tcp", addr).
//
// Only the first inherited fd is used. agentcage exposes one gRPC
// port today; multi-socket activation would need LISTEN_FDNAMES and
// is out of scope.
//
// Activation enables two things: zero-downtime restart, where a new
// orchestrator inherits the existing socket without dropping in-flight
// connections, and privilege separation, where systemd binds the
// (possibly privileged) port and hands the fd to an unprivileged
// agentcage user.
func AcquireListener(addr string) (lis net.Listener, activated bool, err error) {
	if lis, ok, listErr := tryActivatedListener(); listErr != nil {
		return nil, false, listErr
	} else if ok {
		return lis, true, nil
	}

	lis, err = net.Listen("tcp", addr)
	return lis, false, err
}

// tryActivatedListener checks the systemd activation env vars and
// wraps the first inherited fd as a net.Listener if this process is
// the intended target. ok=false with no error means activation is not
// in effect; the caller should fall back to net.Listen.
func tryActivatedListener() (net.Listener, bool, error) {
	pidStr := os.Getenv(listenPIDEnv)
	fdsStr := os.Getenv(listenFDsEnv)
	if pidStr == "" || fdsStr == "" {
		return nil, false, nil
	}

	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		return nil, false, fmt.Errorf("LISTEN_PID=%q is not a valid integer", pidStr)
	}
	if pid != os.Getpid() {
		// systemd's safety check. The env vars are inherited across
		// fork/exec, so a child process has to verify the activation
		// was meant for it. If pids don't match, ignore activation
		// and fall back to net.Listen.
		return nil, false, nil
	}

	nfds, err := strconv.Atoi(fdsStr)
	if err != nil {
		return nil, false, fmt.Errorf("LISTEN_FDS=%q is not a valid integer", fdsStr)
	}
	if nfds < 1 {
		return nil, false, nil
	}

	// Take the first inherited fd. Mark close-on-exec so a future
	// child process doesn't accidentally inherit it.
	fd := uintptr(systemdListenFDsStart)
	syscall.CloseOnExec(int(fd))

	f := os.NewFile(fd, fmt.Sprintf("systemd-activated-%d", fd))
	if f == nil {
		return nil, false, fmt.Errorf("os.NewFile returned nil for fd %d", fd)
	}

	lis, err := net.FileListener(f)
	// FileListener dups the fd; close our handle either way.
	_ = f.Close()
	if err != nil {
		return nil, false, fmt.Errorf("wrapping inherited fd %d as net.Listener: %w", fd, err)
	}

	// Clear the env vars so any subprocess we spawn (or a re-entry into
	// AcquireListener) does not try to consume the same fd again. This
	// matches sd_listen_fds(3)'s unset_environment=1 recommendation.
	_ = os.Unsetenv(listenPIDEnv)
	_ = os.Unsetenv(listenFDsEnv)

	return lis, true, nil
}
