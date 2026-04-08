// Package enforcement is every runtime safety gate that keeps a cage
// from doing what it wasn't authorized to do. Scope and resource
// bounds are checked twice, once in Go and once in OPA, so a bypass
// of one layer is caught by the other.
//
// The package owns five concerns. Go-side validation in validate.go
// catches structural problems (empty scope, private CIDRs, negative
// rate limits) before OPA ever runs. The OPA engine in opa.go
// evaluates scope, cage config, payload patterns, and compliance
// frameworks against Rego policies generated from config at startup
// (regogen.go). Falco rules are generated the same way (falcogen.go)
// and the runtime alert handler routes each rule to a tripwire policy
// (log, escalate to human, or immediate teardown). nftables egress
// rules are applied per cage by NFTablesEnforcer in network.go. The
// in-cage DNS resolver allowlist is built in dns.go.
//
// Any failure to enforce here means an unscoped cage. Bias toward
// fail-closed.
package enforcement
