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
		name            string
		scope           cage.Scope
		llmEndpoint     string
		natsAddr        string
		wantDomains     []string
		wantLLMEndpoint string
		wantNATS        string
	}{
		{
			name: "scope with domain hosts",
			scope: cage.Scope{
				Hosts: []string{"example.com", "api.target.io"},
			},
			llmEndpoint:     "llm.internal:8080",
			natsAddr:        "nats.internal:4222",
			wantDomains:     []string{"example.com", "api.target.io"},
			wantLLMEndpoint: "llm.internal:8080",
			wantNATS:        "nats.internal:4222",
		},
		{
			name: "scope with IP hosts filtered out",
			scope: cage.Scope{
				Hosts: []string{"192.168.1.1", "example.com", "10.0.0.1"},
			},
			llmEndpoint:     "llm.internal:8080",
			natsAddr:        "nats.internal:4222",
			wantDomains:     []string{"example.com"},
			wantLLMEndpoint: "llm.internal:8080",
			wantNATS:        "nats.internal:4222",
		},
		{
			name: "scope with only IPs yields no allowed domains",
			scope: cage.Scope{
				Hosts: []string{"10.0.0.1", "172.16.0.1"},
			},
			llmEndpoint:     "llm.internal:8080",
			natsAddr:        "nats.internal:4222",
			wantDomains:     nil,
			wantLLMEndpoint: "llm.internal:8080",
			wantNATS:        "nats.internal:4222",
		},
		{
			name:            "empty scope yields only LLM endpoint and NATS",
			scope:           cage.Scope{},
			llmEndpoint:     "llm.internal:8080",
			natsAddr:        "nats.internal:4222",
			wantDomains:     nil,
			wantLLMEndpoint: "llm.internal:8080",
			wantNATS:        "nats.internal:4222",
		},
		{
			name: "IPv6 addresses filtered out",
			scope: cage.Scope{
				Hosts: []string{"::1", "example.com", "fe80::1"},
			},
			llmEndpoint:     "llm.internal:8080",
			natsAddr:        "nats.internal:4222",
			wantDomains:     []string{"example.com"},
			wantLLMEndpoint: "llm.internal:8080",
			wantNATS:        "nats.internal:4222",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := GenerateDNSConfig(tt.scope, tt.llmEndpoint, tt.natsAddr)

			assert.Equal(t, tt.wantDomains, config.AllowedDomains)
			assert.Equal(t, tt.wantLLMEndpoint, config.LLMEndpoint)
			assert.Equal(t, tt.wantNATS, config.NATSAddr)
		})
	}
}

func TestGenerateResolverConf(t *testing.T) {
	t.Run("includes all allowed domains", func(t *testing.T) {
		config := DNSConfig{
			AllowedDomains: []string{"example.com", "api.target.io"},
			LLMEndpoint:    "llm.internal:8080",
			NATSAddr:       "nats.internal:4222",
		}

		result := string(GenerateResolverConf(config))

		assert.Contains(t, result, "allow example.com")
		assert.Contains(t, result, "allow api.target.io")
		assert.Contains(t, result, "llm llm.internal:8080")
		assert.Contains(t, result, "nats nats.internal:4222")
	})

	t.Run("each entry on its own line", func(t *testing.T) {
		config := DNSConfig{
			AllowedDomains: []string{"a.com", "b.com", "c.com"},
			LLMEndpoint:    "gw:8080",
			NATSAddr:       "nats:4222",
		}

		result := string(GenerateResolverConf(config))
		lines := strings.Split(strings.TrimSpace(result), "\n")

		require.Len(t, lines, 5)
		assert.Equal(t, "llm gw:8080", lines[0])
		assert.Equal(t, "nats nats:4222", lines[1])
		assert.Equal(t, "allow a.com", lines[2])
		assert.Equal(t, "allow b.com", lines[3])
		assert.Equal(t, "allow c.com", lines[4])
	})

	t.Run("empty allowed domains produces only service entries", func(t *testing.T) {
		config := DNSConfig{
			LLMEndpoint: "gw:8080",
			NATSAddr:    "nats:4222",
		}

		result := string(GenerateResolverConf(config))
		lines := strings.Split(strings.TrimSpace(result), "\n")

		require.Len(t, lines, 2)
		assert.Equal(t, "llm gw:8080", lines[0])
		assert.Equal(t, "nats nats:4222", lines[1])
	})
}
