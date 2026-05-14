//go:build !linux

package main

import "net/http"

// proxyTransport returns the default transport on non-Linux platforms.
// SO_MARK is Linux-only; the iptables redirect loop only exists inside
// Firecracker VMs which are always Linux.
func proxyTransport() *http.Transport {
	return http.DefaultTransport.(*http.Transport).Clone()
}
