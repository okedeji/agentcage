//go:build !linux

package main

import (
	"fmt"
	"net"
)

const vsockCIDHost = 2

func dialVsock(cid, port uint32) (net.Conn, error) {
	sockPath := fmt.Sprintf("/var/run/agentcage/vsock-%d.sock", port)
	return net.Dial("unix", sockPath)
}

func dialVsockRetry(port uint32) (net.Conn, error) {
	return dialVsock(vsockCIDHost, port)
}
