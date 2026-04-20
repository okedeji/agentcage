//go:build !linux

package main

import (
	"fmt"
	"net"
)

const vsockCIDHost = 2

type vsockListener struct {
	inner net.Listener
}

// listenVsock falls back to a Unix socket on non-Linux. This lets the
// binary compile and vet on macOS; it only runs for real inside a
// Firecracker guest (Linux).
func listenVsock(port uint32) (*vsockListener, error) {
	sockPath := fmt.Sprintf("/var/run/agentcage/vsock-%d.sock", port)
	lis, err := net.Listen("unix", sockPath)
	if err != nil {
		return nil, err
	}
	return &vsockListener{inner: lis}, nil
}

func (l *vsockListener) Accept() (net.Conn, error) { return l.inner.Accept() }
func (l *vsockListener) Close() error               { return l.inner.Close() }

func dialVsock(cid, port uint32) (net.Conn, error) {
	sockPath := fmt.Sprintf("/var/run/agentcage/vsock-%d.sock", port)
	return net.Dial("unix", sockPath)
}
