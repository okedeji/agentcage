//go:build linux

package main

import (
	"net"
	"net/http"
	"syscall"
	"time"
)

// proxyTransport clones http.DefaultTransport (inheriting TLS timeouts,
// HTTP/2, keepalive, etc.) and overrides the dialer to set fwmark 1 on
// every outbound socket. cage-init inserts an iptables rule that skips
// the REDIRECT target for marked packets, so the proxy's upstream
// connections reach the real target instead of looping back through
// port 8080.
func proxyTransport() *http.Transport {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.DialContext = (&net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
		Control: func(_, _ string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				_ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, 1)
			})
		},
	}).DialContext
	return t
}
