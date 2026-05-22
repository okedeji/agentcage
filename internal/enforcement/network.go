package enforcement

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/go-logr/logr"

	"github.com/okedeji/agentcage/internal/cage"
)

// NetworkEnforcer manages network isolation for cages.
type NetworkEnforcer interface {
	Apply(ctx context.Context, cageID string, scope cage.Scope, extras []string, tapDevice string) error
	Remove(ctx context.Context, cageID string) error
}

// AllowEntry is a single (CIDR, ports) pair in a cage's allow list.
// Each entry carries its own port restriction because targets, the
// webhook, NATS, and any other extras run on different ports. A
// single global port list (the prior shape) silently restricted the
// webhook to whatever ports the operator's target used — typically
// 443 — and dropped LLM traffic at the cage's egress filter.
type AllowEntry struct {
	CIDR  string
	Ports []string // empty means any TCP port
}

// EgressRule is a deployment-agnostic representation of a cage's allowed
// network destinations. The enforcer translates this to nftables rules.
type EgressRule struct {
	CageID     string
	TAPDevice  string
	Allows     []AllowEntry
	AllowFQDNs []string
}

// AllowIPs returns just the CIDRs from Allows. Kept for tests and
// callers that only care about reachable destinations.
func (r EgressRule) AllowIPs() []string {
	out := make([]string, len(r.Allows))
	for i, a := range r.Allows {
		out[i] = a.CIDR
	}
	return out
}

// BuildEgressRules parses scope + extras into structured egress rules.
// Resolves FQDNs to IPs so nftables can enforce at the network
// layer. The DNS resolver inside the cage is the primary control;
// resolved IPs here are a second layer for hardcoded-IP bypass.
//
// Port handling: the target uses scope.Ports (operator-supplied,
// typically ["443"] for HTTPS pentests). Each extra URL carries its
// own port — extracted from the URL or defaulted from the scheme —
// because the LLM webhook, judge webhook, and NATS each live on a
// different port from the target.
func BuildEgressRules(cageID string, scope cage.Scope, extras []string, tapDevice string) EgressRule {
	rule := EgressRule{CageID: cageID, TAPDevice: tapDevice}

	addEntry := func(host string, ports []string) {
		if host == "" {
			return
		}
		// Extras may be full URLs (e.g. "https://api.openai.com/v1").
		// Extract the hostname so DNS lookup and nftables work.
		if strings.Contains(host, "://") {
			if u, err := url.Parse(host); err == nil && u.Hostname() != "" {
				host = u.Hostname()
			}
		}
		// Strip port if present (e.g. "nats.internal:4222").
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		if ip := net.ParseIP(host); ip != nil {
			cidr := host + "/32"
			if ip.To4() == nil {
				cidr = host + "/128"
			}
			rule.Allows = append(rule.Allows, AllowEntry{CIDR: cidr, Ports: ports})
			return
		}
		rule.AllowFQDNs = append(rule.AllowFQDNs, host)
		addrs, err := net.LookupHost(host)
		if err != nil {
			return
		}
		for _, addr := range addrs {
			ip := net.ParseIP(addr)
			if ip == nil {
				continue
			}
			cidr := addr + "/32"
			if ip.To4() == nil {
				cidr = addr + "/128"
			}
			rule.Allows = append(rule.Allows, AllowEntry{CIDR: cidr, Ports: ports})
		}
	}

	// Target gets the operator-supplied ports list (empty = any port).
	addEntry(scope.Host, scope.Ports)

	// Each extra carries its own port. "http://10.0.0.157:8082/llm"
	// → port 8082. "nats.internal:4222" → port 4222. Bare hostnames
	// fall back to any-port.
	for _, ex := range extras {
		addEntry(ex, extraPorts(ex))
	}

	return rule
}

// extraPorts returns the single TCP port for an extra URL or
// host:port pair. Empty when no port can be derived — the resulting
// AllowEntry then permits any port to that CIDR, which is the safe
// fallback for operator-supplied bare hostnames.
func extraPorts(raw string) []string {
	if raw == "" {
		return nil
	}
	if strings.Contains(raw, "://") {
		u, err := url.Parse(raw)
		if err != nil {
			return nil
		}
		if p := u.Port(); p != "" {
			return []string{p}
		}
		switch u.Scheme {
		case "https":
			return []string{"443"}
		case "http":
			return []string{"80"}
		}
		return nil
	}
	if _, port, err := net.SplitHostPort(raw); err == nil && port != "" {
		return []string{port}
	}
	return nil
}

// NFTablesEnforcer applies network isolation using nftables rules on the host.
// Each cage VM gets a TAP device; rules restrict that device's egress to the
// allowed IPs, FQDNs, and ports.
type NFTablesEnforcer struct {
	log logr.Logger
}

func NewNFTablesEnforcer(log logr.Logger) *NFTablesEnforcer {
	return &NFTablesEnforcer{log: log.WithValues("component", "nftables")}
}

// NoopEnforcer is the network enforcer used when cages run unisolated (dev
// mode without KVM/Firecracker). It logs and does nothing, since there is
// no TAP device to attach rules to.
type NoopEnforcer struct {
	log logr.Logger
}

func NewNoopEnforcer(log logr.Logger) *NoopEnforcer {
	return &NoopEnforcer{log: log.WithValues("component", "noop-enforcer")}
}

func (e *NoopEnforcer) Apply(_ context.Context, cageID string, _ cage.Scope, _ []string, _ string) error {
	e.log.Info("noop network enforcement: cage has no isolation", "cage_id", cageID)
	return nil
}

func (e *NoopEnforcer) Remove(_ context.Context, _ string) error {
	return nil
}

func (e *NFTablesEnforcer) Apply(ctx context.Context, cageID string, scope cage.Scope, extras []string, tapDevice string) error {
	if tapDevice == "" {
		return fmt.Errorf("cage %s: TAP device name required for nftables enforcement", cageID)
	}
	rules := BuildEgressRules(cageID, scope, extras, tapDevice)
	nft := GenerateNFTRules(rules)
	e.log.V(1).Info("applying nftables rules", "cage_id", cageID, "tap", tapDevice, "rule_count", strings.Count(nft, "\n"))

	// Delete existing rules for this cage first so retries are idempotent.
	_ = e.Remove(ctx, cageID)

	return e.execNFT(ctx, cageID, nft)
}

func (e *NFTablesEnforcer) Remove(ctx context.Context, cageID string) error {
	tableName := fmt.Sprintf("cage-%s", cageID)
	e.log.V(1).Info("removing nftables rules", "cage_id", cageID, "table", tableName)

	cmd := exec.CommandContext(ctx, "nft", "delete", "table", "inet", tableName)
	output, err := cmd.CombinedOutput()
	if err != nil {
		if strings.Contains(string(output), "No such file or directory") {
			return nil
		}
		return fmt.Errorf("cage %s: deleting nftables table %s: %s: %w", cageID, tableName, string(output), err)
	}
	return nil
}

func (e *NFTablesEnforcer) execNFT(ctx context.Context, cageID, rules string) error {
	dir := os.TempDir()
	ruleFile := filepath.Join(dir, fmt.Sprintf("cage-%s.nft", cageID))

	if err := os.WriteFile(ruleFile, []byte(rules), 0600); err != nil {
		return fmt.Errorf("cage %s: writing nftables rules: %w", cageID, err)
	}
	defer func() { _ = os.Remove(ruleFile) }()

	cmd := exec.CommandContext(ctx, "nft", "-f", ruleFile)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("cage %s: applying nftables rules: %s: %w", cageID, string(output), err)
	}
	e.log.Info("nftables rules applied", "cage_id", cageID)
	return nil
}

// GenerateNFTRules produces nftables rule text for a cage's egress policy.
// Rules hook the forward chain and filter by the cage's TAP device so
// only this cage's forwarded traffic is restricted. Other cages and
// host-originated traffic pass through unaffected.
func GenerateNFTRules(rule EgressRule) string {
	var b strings.Builder

	tableName := fmt.Sprintf("cage-%s", rule.CageID)
	fmt.Fprintf(&b, "table inet %s {\n", tableName)

	// Cage traffic is forwarded (TAP → host → internet), not locally
	// originated, so rules must be on the forward hook. policy accept
	// lets non-cage traffic through; the iifname guard below restricts
	// only packets entering from this cage's TAP device.
	b.WriteString("  chain forward {\n")
	b.WriteString("    type filter hook forward priority 0; policy accept;\n\n")

	// Pass traffic not originating from this cage's TAP device.
	fmt.Fprintf(&b, "    iifname != \"%s\" accept\n\n", rule.TAPDevice)

	// Allow return traffic for connections the cage initiated.
	b.WriteString("    ct state established,related accept\n\n")

	// Allow DNS so the cage can resolve allowed hostnames.
	if len(rule.AllowFQDNs) > 0 {
		b.WriteString("    udp dport 53 accept\n")
		b.WriteString("    tcp dport 53 accept\n\n")
	}

	// Per-(CIDR, ports) accept lines. Each AllowEntry carries its own
	// port list because the target, the webhook, NATS, and any other
	// extra each listens on a different port; a single global port
	// filter silently dropped LLM traffic in the prior shape.
	for _, a := range rule.Allows {
		family := "ip"
		if strings.Contains(a.CIDR, ":") {
			family = "ip6"
		}
		if len(a.Ports) > 0 {
			ports := strings.Join(a.Ports, ", ")
			fmt.Fprintf(&b, "    %s daddr %s tcp dport { %s } accept\n", family, a.CIDR, ports)
		} else {
			fmt.Fprintf(&b, "    %s daddr %s accept\n", family, a.CIDR)
		}
	}

	// Everything else from this cage is denied.
	b.WriteString("\n    drop\n")
	b.WriteString("  }\n")
	b.WriteString("}\n")

	return b.String()
}
