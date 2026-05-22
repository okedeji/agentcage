package enforcement

import (
	"strings"
	"testing"

	"github.com/okedeji/agentcage/internal/cage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildEgressRules_DomainHost(t *testing.T) {
	scope := cage.Scope{Host: "example.com"}
	rules := BuildEgressRules("abc-123", scope, nil, "tap-deadbeef")

	assert.Equal(t, "abc-123", rules.CageID)
	assert.Equal(t, "tap-deadbeef", rules.TAPDevice)
	require.Len(t, rules.AllowFQDNs, 1)
	assert.Equal(t, "example.com", rules.AllowFQDNs[0])
	assert.NotEmpty(t, rules.AllowIPs())
}

func TestBuildEgressRules_IPHost(t *testing.T) {
	scope := cage.Scope{Host: "93.184.216.34"}
	rules := BuildEgressRules("ip-cage", scope, nil, "tap-00000001")

	assert.Empty(t, rules.AllowFQDNs)
	require.Len(t, rules.Allows, 1)
	assert.Equal(t, "93.184.216.34/32", rules.Allows[0].CIDR)
	assert.Empty(t, rules.Allows[0].Ports, "no scope.Ports → any-port allow for target")
}

func TestBuildEgressRules_WithExtras(t *testing.T) {
	scope := cage.Scope{Host: "target.com"}
	extras := []string{"gateway.internal.svc", "10.0.0.50"}
	rules := BuildEgressRules("extras", scope, extras, "tap-00000003")

	require.Len(t, rules.AllowFQDNs, 2)
	assert.Equal(t, "target.com", rules.AllowFQDNs[0])
	assert.Equal(t, "gateway.internal.svc", rules.AllowFQDNs[1])
	assert.Contains(t, rules.AllowIPs(), "10.0.0.50/32")
}

func TestBuildEgressRules_WithPorts(t *testing.T) {
	scope := cage.Scope{
		Host:  "example.com",
		Ports: []string{"80", "443"},
	}
	rules := BuildEgressRules("ports", scope, nil, "tap-00000004")

	// Target IP(s) carry the scope.Ports.
	require.NotEmpty(t, rules.Allows)
	assert.ElementsMatch(t, []string{"80", "443"}, rules.Allows[0].Ports)
}

func TestBuildEgressRules_PerExtraPort(t *testing.T) {
	// This is the regression: prior shape applied scope.Ports
	// (e.g. ["443"]) to every CIDR including the LLM webhook which
	// actually listens on 8082. The cage's nftables filter then
	// dropped LLM traffic.
	scope := cage.Scope{
		Host:  "10.1.1.1",
		Ports: []string{"443"},
	}
	extras := []string{
		"http://10.0.0.157:8082/llm",
		"http://10.0.0.157:8082/judge",
		"nats.internal:4222",
		"https://api.openai.com/v1/chat/completions",
	}
	rules := BuildEgressRules("multi-extra", scope, extras, "tap-00000007")

	byCIDR := map[string][]string{}
	for _, a := range rules.Allows {
		byCIDR[a.CIDR] = a.Ports
	}
	assert.Equal(t, []string{"443"}, byCIDR["10.1.1.1/32"], "target uses scope.Ports")
	assert.Equal(t, []string{"8082"}, byCIDR["10.0.0.157/32"], "webhook port from URL, not target's 443")
	// nats.internal:4222 → resolves via DNS, but even when LookupHost
	// fails the port should be derived per-extra.
	for _, a := range rules.Allows {
		if a.CIDR == "10.0.0.157/32" {
			assert.Equal(t, []string{"8082"}, a.Ports)
		}
	}
}

func TestBuildEgressRules_Empty(t *testing.T) {
	rules := BuildEgressRules("empty", cage.Scope{}, nil, "tap-00000005")
	assert.Empty(t, rules.Allows)
	assert.Empty(t, rules.AllowFQDNs)
}

func TestGenerateNFTRules_Structure(t *testing.T) {
	rule := EgressRule{
		CageID:     "test-123",
		TAPDevice:  "tap-abcd1234",
		Allows:     []AllowEntry{{CIDR: "93.184.216.34/32", Ports: []string{"80", "443"}}},
		AllowFQDNs: []string{"example.com"},
	}

	nft := GenerateNFTRules(rule)

	assert.Contains(t, nft, "table inet cage-test-123")
	assert.Contains(t, nft, "hook forward")
	assert.Contains(t, nft, "policy accept")
	assert.Contains(t, nft, `iifname != "tap-abcd1234" accept`)
	assert.Contains(t, nft, "ct state established,related accept")
	assert.NotContains(t, nft, "oifname lo")
	assert.Contains(t, nft, "93.184.216.34/32")
	assert.Contains(t, nft, "udp dport 53 accept")
	assert.Contains(t, nft, "tcp dport { 80, 443 }")
	assert.Contains(t, nft, "drop")
}

func TestGenerateNFTRules_NoPortRestriction(t *testing.T) {
	rule := EgressRule{
		CageID:    "no-ports",
		TAPDevice: "tap-00001111",
		Allows:    []AllowEntry{{CIDR: "10.0.0.1/32"}},
	}

	nft := GenerateNFTRules(rule)
	assert.Contains(t, nft, "10.0.0.1/32 accept")
	assert.NotContains(t, nft, "tcp dport {")
}

func TestGenerateNFTRules_PerEntryPorts(t *testing.T) {
	// The bug fix: target on 443, webhook on 8082, both rendered
	// with their respective ports.
	rule := EgressRule{
		CageID:    "mixed",
		TAPDevice: "tap-22220000",
		Allows: []AllowEntry{
			{CIDR: "1.2.3.4/32", Ports: []string{"443"}},
			{CIDR: "10.0.0.157/32", Ports: []string{"8082"}},
		},
	}
	nft := GenerateNFTRules(rule)
	assert.Contains(t, nft, "ip daddr 1.2.3.4/32 tcp dport { 443 } accept")
	assert.Contains(t, nft, "ip daddr 10.0.0.157/32 tcp dport { 8082 } accept")
}

func TestGenerateNFTRules_DNSOnlyForFQDNs(t *testing.T) {
	ruleWithFQDN := EgressRule{CageID: "a", TAPDevice: "tap-aaaa0000", AllowFQDNs: []string{"example.com"}}
	ruleIPOnly := EgressRule{CageID: "b", TAPDevice: "tap-bbbb0000", Allows: []AllowEntry{{CIDR: "1.2.3.4/32"}}}

	assert.True(t, strings.Contains(GenerateNFTRules(ruleWithFQDN), "dport 53"))
	assert.False(t, strings.Contains(GenerateNFTRules(ruleIPOnly), "dport 53"))
}
