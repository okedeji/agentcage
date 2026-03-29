package enforcement

import (
	"strings"
	"testing"

	"github.com/okedeji/agentcage/internal/cage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateDNSConfig(t *testing.T) {
	tests := []struct {
		name           string
		scope          cage.Scope
		gatewayAddr    string
		natsAddr       string
		wantDomains    []string
		wantGateway    string
		wantNATS       string
	}{
		{
			name: "scope with domain hosts",
			scope: cage.Scope{
				Hosts: []string{"example.com", "api.target.io"},
			},
			gatewayAddr: "gateway.internal:8080",
			natsAddr:    "nats.internal:4222",
			wantDomains: []string{"example.com", "api.target.io"},
			wantGateway: "gateway.internal:8080",
			wantNATS:    "nats.internal:4222",
		},
		{
			name: "scope with IP hosts filtered out",
			scope: cage.Scope{
				Hosts: []string{"192.168.1.1", "example.com", "10.0.0.1"},
			},
			gatewayAddr: "gateway.internal:8080",
			natsAddr:    "nats.internal:4222",
			wantDomains: []string{"example.com"},
			wantGateway: "gateway.internal:8080",
			wantNATS:    "nats.internal:4222",
		},
		{
			name: "scope with only IPs yields no allowed domains",
			scope: cage.Scope{
				Hosts: []string{"10.0.0.1", "172.16.0.1"},
			},
			gatewayAddr: "gateway.internal:8080",
			natsAddr:    "nats.internal:4222",
			wantDomains: nil,
			wantGateway: "gateway.internal:8080",
			wantNATS:    "nats.internal:4222",
		},
		{
			name:        "empty scope yields only gateway and NATS",
			scope:       cage.Scope{},
			gatewayAddr: "gateway.internal:8080",
			natsAddr:    "nats.internal:4222",
			wantDomains: nil,
			wantGateway: "gateway.internal:8080",
			wantNATS:    "nats.internal:4222",
		},
		{
			name: "IPv6 addresses filtered out",
			scope: cage.Scope{
				Hosts: []string{"::1", "example.com", "fe80::1"},
			},
			gatewayAddr: "gateway.internal:8080",
			natsAddr:    "nats.internal:4222",
			wantDomains: []string{"example.com"},
			wantGateway: "gateway.internal:8080",
			wantNATS:    "nats.internal:4222",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := GenerateDNSConfig(tt.scope, tt.gatewayAddr, tt.natsAddr)

			assert.Equal(t, tt.wantDomains, config.AllowedDomains)
			assert.Equal(t, tt.wantGateway, config.GatewayAddr)
			assert.Equal(t, tt.wantNATS, config.NATSAddr)
		})
	}
}

func TestGenerateResolverConf(t *testing.T) {
	t.Run("includes all allowed domains", func(t *testing.T) {
		config := DNSConfig{
			AllowedDomains: []string{"example.com", "api.target.io"},
			GatewayAddr:    "gateway.internal:8080",
			NATSAddr:       "nats.internal:4222",
		}

		result := string(GenerateResolverConf(config))

		assert.Contains(t, result, "allow example.com")
		assert.Contains(t, result, "allow api.target.io")
		assert.Contains(t, result, "gateway gateway.internal:8080")
		assert.Contains(t, result, "nats nats.internal:4222")
	})

	t.Run("each entry on its own line", func(t *testing.T) {
		config := DNSConfig{
			AllowedDomains: []string{"a.com", "b.com", "c.com"},
			GatewayAddr:    "gw:8080",
			NATSAddr:       "nats:4222",
		}

		result := string(GenerateResolverConf(config))
		lines := strings.Split(strings.TrimSpace(result), "\n")

		require.Len(t, lines, 5)
		assert.Equal(t, "gateway gw:8080", lines[0])
		assert.Equal(t, "nats nats:4222", lines[1])
		assert.Equal(t, "allow a.com", lines[2])
		assert.Equal(t, "allow b.com", lines[3])
		assert.Equal(t, "allow c.com", lines[4])
	})

	t.Run("empty allowed domains produces only service entries", func(t *testing.T) {
		config := DNSConfig{
			GatewayAddr: "gw:8080",
			NATSAddr:    "nats:4222",
		}

		result := string(GenerateResolverConf(config))
		lines := strings.Split(strings.TrimSpace(result), "\n")

		require.Len(t, lines, 2)
		assert.Equal(t, "gateway gw:8080", lines[0])
		assert.Equal(t, "nats nats:4222", lines[1])
	})
}
