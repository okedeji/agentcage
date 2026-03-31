package enforcement

import (
	"strings"
	"testing"

	"github.com/okedeji/agentcage/internal/cage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildEgressRules_DomainHosts(t *testing.T) {
	scope := cage.Scope{Hosts: []string{"example.com", "api.target.io"}}
	rules := BuildEgressRules("abc-123", scope, nil)

	assert.Equal(t, "abc-123", rules.CageID)
	assert.Empty(t, rules.AllowIPs)
	require.Len(t, rules.AllowFQDNs, 2)
	assert.Equal(t, "example.com", rules.AllowFQDNs[0])
	assert.Equal(t, "api.target.io", rules.AllowFQDNs[1])
}

func TestBuildEgressRules_IPHosts(t *testing.T) {
	scope := cage.Scope{Hosts: []string{"93.184.216.34", "2001:db8::1"}}
	rules := BuildEgressRules("ip-cage", scope, nil)

	assert.Empty(t, rules.AllowFQDNs)
	require.Len(t, rules.AllowIPs, 2)
	assert.Equal(t, "93.184.216.34/32", rules.AllowIPs[0])
	assert.Equal(t, "2001:db8::1/128", rules.AllowIPs[1])
}

func TestBuildEgressRules_MixedHosts(t *testing.T) {
	scope := cage.Scope{Hosts: []string{"example.com", "93.184.216.34"}}
	rules := BuildEgressRules("mixed", scope, nil)

	require.Len(t, rules.AllowFQDNs, 1)
	assert.Equal(t, "example.com", rules.AllowFQDNs[0])
	require.Len(t, rules.AllowIPs, 1)
	assert.Equal(t, "93.184.216.34/32", rules.AllowIPs[0])
}

func TestBuildEgressRules_WithExtras(t *testing.T) {
	scope := cage.Scope{Hosts: []string{"target.com"}}
	extras := []string{"gateway.internal.svc", "10.0.0.50"}
	rules := BuildEgressRules("extras", scope, extras)

	require.Len(t, rules.AllowFQDNs, 2)
	assert.Equal(t, "target.com", rules.AllowFQDNs[0])
	assert.Equal(t, "gateway.internal.svc", rules.AllowFQDNs[1])
	require.Len(t, rules.AllowIPs, 1)
	assert.Equal(t, "10.0.0.50/32", rules.AllowIPs[0])
}

func TestBuildEgressRules_WithPorts(t *testing.T) {
	scope := cage.Scope{
		Hosts: []string{"example.com"},
		Ports: []string{"80", "443"},
	}
	rules := BuildEgressRules("ports", scope, nil)

	require.Len(t, rules.AllowPorts, 2)
	assert.Equal(t, "80", rules.AllowPorts[0])
	assert.Equal(t, "443", rules.AllowPorts[1])
}

func TestBuildEgressRules_Empty(t *testing.T) {
	rules := BuildEgressRules("empty", cage.Scope{}, nil)
	assert.Empty(t, rules.AllowIPs)
	assert.Empty(t, rules.AllowFQDNs)
	assert.Empty(t, rules.AllowPorts)
}

func TestGenerateNFTRules_Structure(t *testing.T) {
	rule := EgressRule{
		CageID:     "test-123",
		AllowIPs:   []string{"93.184.216.34/32"},
		AllowFQDNs: []string{"example.com"},
		AllowPorts: []string{"80", "443"},
	}

	nft := GenerateNFTRules(rule)

	assert.Contains(t, nft, "table inet cage-test-123")
	assert.Contains(t, nft, "policy drop")
	assert.Contains(t, nft, "ct state established,related accept")
	assert.Contains(t, nft, "oifname lo accept")
	assert.Contains(t, nft, "93.184.216.34/32")
	assert.Contains(t, nft, "udp dport 53 accept")
	assert.Contains(t, nft, "tcp dport { 80, 443 }")
}

func TestGenerateNFTRules_NoPortRestriction(t *testing.T) {
	rule := EgressRule{
		CageID:   "no-ports",
		AllowIPs: []string{"10.0.0.1/32"},
	}

	nft := GenerateNFTRules(rule)
	assert.Contains(t, nft, "10.0.0.1/32")
	assert.NotContains(t, nft, "tcp dport {")
}

func TestGenerateNFTRules_DNSOnlyForFQDNs(t *testing.T) {
	ruleWithFQDN := EgressRule{CageID: "a", AllowFQDNs: []string{"example.com"}}
	ruleIPOnly := EgressRule{CageID: "b", AllowIPs: []string{"1.2.3.4/32"}}

	assert.True(t, strings.Contains(GenerateNFTRules(ruleWithFQDN), "dport 53"))
	assert.False(t, strings.Contains(GenerateNFTRules(ruleIPOnly), "dport 53"))
}
