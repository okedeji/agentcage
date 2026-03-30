package enforcement

import (
	"fmt"
	"net"
	"strings"

	"github.com/okedeji/agentcage/internal/cage"
)

type DNSConfig struct {
	AllowedDomains []string
	LLMEndpoint    string
	NATSAddr       string
}

// GenerateDNSConfig creates a DNS configuration from a cage's scope and
// the platform service addresses. IP addresses in the scope are filtered
// out because DNS resolution only applies to domain names.
func GenerateDNSConfig(scope cage.Scope, llmEndpoint, natsAddr string) DNSConfig {
	var domains []string
	for _, host := range scope.Hosts {
		if net.ParseIP(host) != nil {
			continue
		}
		domains = append(domains, host)
	}

	return DNSConfig{
		AllowedDomains: domains,
		LLMEndpoint:    llmEndpoint,
		NATSAddr:       natsAddr,
	}
}

// GenerateResolverConf produces the configuration file content for the
// controlled DNS resolver inside the cage. Queries for unlisted domains
// return NXDOMAIN.
func GenerateResolverConf(config DNSConfig) []byte {
	var b strings.Builder

	fmt.Fprintf(&b, "llm %s\n", config.LLMEndpoint)
	fmt.Fprintf(&b, "nats %s\n", config.NATSAddr)

	for _, domain := range config.AllowedDomains {
		fmt.Fprintf(&b, "allow %s\n", domain)
	}

	return []byte(b.String())
}
