package enforcement

import (
	"context"
	"fmt"
	"net"

	"github.com/okedeji/agentcage/internal/cage"
)

type NetworkEnforcer interface {
	Apply(ctx context.Context, cageID string, scope cage.Scope, extras []string) error
	Remove(ctx context.Context, cageID string) error
}

// EgressPolicy is a deployment-agnostic representation of a cage's network
// egress rules. The wiring layer converts this to the appropriate format:
// Cilium standalone API JSON for bare metal/on-prem, EgressPolicy
// CRD for Kubernetes mode.
type EgressPolicy struct {
	Name     string            `json:"name"`
	Labels   map[string]string `json:"labels"`
	Selector map[string]string `json:"selector"`
	Egress   []CiliumEgress    `json:"egress"`
}

type CiliumEgress struct {
	ToFQDNs []CiliumFQDN `json:"toFQDNs,omitempty" yaml:"toFQDNs,omitempty"`
	ToPorts []CiliumPort `json:"toPorts,omitempty" yaml:"toPorts,omitempty"`
	ToCIDRs []string     `json:"toCIDRs,omitempty" yaml:"toCIDRs,omitempty"`
}

type CiliumFQDN struct {
	MatchName string `json:"matchName,omitempty" yaml:"matchName,omitempty"`
}

type CiliumPort struct {
	Ports []CiliumPortEntry `json:"ports" yaml:"ports"`
}

type CiliumPortEntry struct {
	Port     string `json:"port" yaml:"port"`
	Protocol string `json:"protocol" yaml:"protocol"`
}

func GeneratePolicy(cageID string, scope cage.Scope, extras []string) EgressPolicy {
	policy := EgressPolicy{
		Name:     fmt.Sprintf("cage-%s", cageID),
		Labels:   map[string]string{"cage-id": cageID},
		Selector: map[string]string{"cage-id": cageID},
	}

	allHosts := make([]string, 0, len(scope.Hosts)+len(extras))
	allHosts = append(allHosts, scope.Hosts...)
	allHosts = append(allHosts, extras...)

	if len(allHosts) == 0 {
		return policy
	}

	egress := CiliumEgress{}
	for _, host := range allHosts {
		if ip := net.ParseIP(host); ip != nil {
			cidr := host + "/32"
			if ip.To4() == nil {
				cidr = host + "/128"
			}
			egress.ToCIDRs = append(egress.ToCIDRs, cidr)
		} else {
			egress.ToFQDNs = append(egress.ToFQDNs, CiliumFQDN{MatchName: host})
		}
	}

	if len(scope.Ports) > 0 {
		port := CiliumPort{}
		for _, p := range scope.Ports {
			port.Ports = append(port.Ports, CiliumPortEntry{Port: p, Protocol: "TCP"})
		}
		egress.ToPorts = append(egress.ToPorts, port)
	}

	policy.Egress = append(policy.Egress, egress)
	return policy
}

type CiliumEnforcer struct{}

func NewCiliumEnforcer() *CiliumEnforcer {
	return &CiliumEnforcer{}
}

func (e *CiliumEnforcer) Apply(ctx context.Context, cageID string, scope cage.Scope, extras []string) error {
	_ = GeneratePolicy(cageID, scope, extras)
	return nil
}

func (e *CiliumEnforcer) Remove(ctx context.Context, cageID string) error {
	return nil
}
