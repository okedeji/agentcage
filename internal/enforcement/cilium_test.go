package enforcement

import (
	"testing"

	"github.com/okedeji/agentcage/internal/cage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGeneratePolicy_DomainHosts(t *testing.T) {
	scope := cage.Scope{Hosts: []string{"example.com", "api.target.io"}}
	policy := GeneratePolicy("abc-123", scope, nil)

	assert.Equal(t, "cage-abc-123", policy.Name)
	assert.Equal(t, map[string]string{"cage-id": "abc-123"}, policy.Labels)
	assert.Equal(t, map[string]string{"cage-id": "abc-123"}, policy.Selector)

	require.Len(t, policy.Egress, 1)
	egress := policy.Egress[0]
	require.Len(t, egress.ToFQDNs, 2)
	assert.Equal(t, "example.com", egress.ToFQDNs[0].MatchName)
	assert.Equal(t, "api.target.io", egress.ToFQDNs[1].MatchName)
	assert.Empty(t, egress.ToCIDRs)
	assert.Empty(t, egress.ToPorts)
}

func TestGeneratePolicy_IPHosts(t *testing.T) {
	scope := cage.Scope{Hosts: []string{"93.184.216.34", "2001:db8::1"}}
	policy := GeneratePolicy("ip-cage", scope, nil)

	require.Len(t, policy.Egress, 1)
	egress := policy.Egress[0]
	assert.Empty(t, egress.ToFQDNs)
	require.Len(t, egress.ToCIDRs, 2)
	assert.Equal(t, "93.184.216.34/32", egress.ToCIDRs[0])
	assert.Equal(t, "2001:db8::1/128", egress.ToCIDRs[1])
}

func TestGeneratePolicy_MixedHosts(t *testing.T) {
	scope := cage.Scope{Hosts: []string{"example.com", "93.184.216.34"}}
	policy := GeneratePolicy("mixed", scope, nil)

	require.Len(t, policy.Egress, 1)
	egress := policy.Egress[0]
	require.Len(t, egress.ToFQDNs, 1)
	assert.Equal(t, "example.com", egress.ToFQDNs[0].MatchName)
	require.Len(t, egress.ToCIDRs, 1)
	assert.Equal(t, "93.184.216.34/32", egress.ToCIDRs[0])
}

func TestGeneratePolicy_WithExtras(t *testing.T) {
	scope := cage.Scope{Hosts: []string{"target.com"}}
	extras := []string{"gateway.internal.svc", "10.0.0.50"}
	policy := GeneratePolicy("extras", scope, extras)

	require.Len(t, policy.Egress, 1)
	egress := policy.Egress[0]
	require.Len(t, egress.ToFQDNs, 2)
	assert.Equal(t, "target.com", egress.ToFQDNs[0].MatchName)
	assert.Equal(t, "gateway.internal.svc", egress.ToFQDNs[1].MatchName)
	require.Len(t, egress.ToCIDRs, 1)
	assert.Equal(t, "10.0.0.50/32", egress.ToCIDRs[0])
}

func TestGeneratePolicy_EmptyHosts(t *testing.T) {
	scope := cage.Scope{}
	policy := GeneratePolicy("empty", scope, nil)

	assert.Equal(t, "cage-empty", policy.Name)
	assert.Empty(t, policy.Egress)
}

func TestGeneratePolicy_WithPorts(t *testing.T) {
	scope := cage.Scope{
		Hosts: []string{"example.com"},
		Ports: []string{"80", "443"},
	}
	policy := GeneratePolicy("ports", scope, nil)

	require.Len(t, policy.Egress, 1)
	egress := policy.Egress[0]
	require.Len(t, egress.ToPorts, 1)
	require.Len(t, egress.ToPorts[0].Ports, 2)
	assert.Equal(t, "80", egress.ToPorts[0].Ports[0].Port)
	assert.Equal(t, "TCP", egress.ToPorts[0].Ports[0].Protocol)
	assert.Equal(t, "443", egress.ToPorts[0].Ports[1].Port)
	assert.Equal(t, "TCP", egress.ToPorts[0].Ports[1].Protocol)
}

func TestGeneratePolicy_NoPorts(t *testing.T) {
	scope := cage.Scope{Hosts: []string{"example.com"}}
	policy := GeneratePolicy("no-ports", scope, nil)

	require.Len(t, policy.Egress, 1)
	assert.Empty(t, policy.Egress[0].ToPorts)
}

func TestGeneratePolicy_LabelsAndName(t *testing.T) {
	policy := GeneratePolicy("test-id-456", cage.Scope{Hosts: []string{"x.com"}}, nil)

	assert.Equal(t, "cage-test-id-456", policy.Name)
	assert.Equal(t, "test-id-456", policy.Labels["cage-id"])
	assert.Equal(t, "test-id-456", policy.Selector["cage-id"])
}
