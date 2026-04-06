package enforcement

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/go-logr/logr"

	"github.com/okedeji/agentcage/internal/cage"
)

// NetworkEnforcer manages network isolation for cages.
type NetworkEnforcer interface {
	Apply(ctx context.Context, cageID string, scope cage.Scope, extras []string) error
	Remove(ctx context.Context, cageID string) error
}

// EgressRule is a deployment-agnostic representation of a cage's allowed
// network destinations. The enforcer translates this to nftables rules.
type EgressRule struct {
	CageID   string
	AllowIPs []string
	AllowFQDNs []string
	AllowPorts []string
}

// BuildEgressRules parses scope + extras into structured egress rules.
func BuildEgressRules(cageID string, scope cage.Scope, extras []string) EgressRule {
	rule := EgressRule{CageID: cageID}

	allHosts := make([]string, 0, len(scope.Hosts)+len(extras))
	allHosts = append(allHosts, scope.Hosts...)
	allHosts = append(allHosts, extras...)

	for _, host := range allHosts {
		if ip := net.ParseIP(host); ip != nil {
			if ip.To4() != nil {
				rule.AllowIPs = append(rule.AllowIPs, host+"/32")
			} else {
				rule.AllowIPs = append(rule.AllowIPs, host+"/128")
			}
		} else {
			rule.AllowFQDNs = append(rule.AllowFQDNs, host)
		}
	}

	rule.AllowPorts = scope.Ports
	return rule
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

func (e *NoopEnforcer) Apply(_ context.Context, cageID string, _ cage.Scope, _ []string) error {
	e.log.Info("noop network enforcement: cage has no isolation", "cage_id", cageID)
	return nil
}

func (e *NoopEnforcer) Remove(_ context.Context, _ string) error {
	return nil
}

func (e *NFTablesEnforcer) Apply(ctx context.Context, cageID string, scope cage.Scope, extras []string) error {
	rules := BuildEgressRules(cageID, scope, extras)
	nft := GenerateNFTRules(rules)
	e.log.V(1).Info("applying nftables rules", "cage_id", cageID, "rule_count", strings.Count(nft, "\n"))

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
func GenerateNFTRules(rule EgressRule) string {
	var b strings.Builder

	tableName := fmt.Sprintf("cage-%s", rule.CageID)
	fmt.Fprintf(&b, "table inet %s {\n", tableName)

	// Default: drop all egress from this cage's TAP device
	b.WriteString("  chain egress {\n")
	b.WriteString("    type filter hook output priority 0; policy drop;\n\n")

	// Allow established/related connections
	b.WriteString("    ct state established,related accept\n\n")

	// Allow loopback (for in-VM communication: proxy, sidecar)
	b.WriteString("    oifname lo accept\n\n")

	// Allow specific IPs
	for _, cidr := range rule.AllowIPs {
		fmt.Fprintf(&b, "    ip daddr %s accept\n", cidr)
	}

	// Allow DNS resolution for FQDNs (port 53)
	if len(rule.AllowFQDNs) > 0 {
		b.WriteString("\n    # DNS resolution for allowed FQDNs\n")
		b.WriteString("    udp dport 53 accept\n")
		b.WriteString("    tcp dport 53 accept\n")
	}

	// Port restrictions (if specified, only allow these ports)
	if len(rule.AllowPorts) > 0 {
		ports := strings.Join(rule.AllowPorts, ", ")
		fmt.Fprintf(&b, "\n    tcp dport { %s } accept\n", ports)
	} else if len(rule.AllowIPs) > 0 || len(rule.AllowFQDNs) > 0 {
		// No port restriction — allow all ports to allowed destinations
		b.WriteString("\n    # No port restriction — all ports allowed to permitted destinations\n")
	}

	b.WriteString("  }\n")
	b.WriteString("}\n")

	return b.String()
}
