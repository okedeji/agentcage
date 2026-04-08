// Package grpc is the orchestrator's gRPC surface and the plumbing
// that supports it. It owns the proto-to-domain adapters that wire
// the generated services to internal/cage, internal/assessment,
// internal/intervention, and internal/fleet; the recovery and
// logging interceptors; the SPIRE-mTLS and file-TLS server config;
// the reloadable cert holder for SIGHUP rotation; the systemd socket
// activation acquirer; and the proxy that forwards CLI commands from
// the agentcage binary to a running orchestrator.
//
// All conversion between proto types and domain types lives in
// convert.go and adapters.go. The rest of the package is the
// connection-level concerns the gRPC server needs but the domain
// services should not have to know about.
package grpc
