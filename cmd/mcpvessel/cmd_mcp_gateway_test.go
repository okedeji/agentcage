package main

import (
	"strings"
	"testing"
)

func TestMCPGatewayConfigFromEnv_RequiresConfig(t *testing.T) {
	t.Setenv("VESSEL_MCP_CONFIG", "")
	if _, err := mcpGatewayConfigFromEnv(); err == nil {
		t.Fatal("expected an error when VESSEL_MCP_CONFIG is unset")
	}
}

func TestMCPGatewayConfigFromEnv_ParsesEdges(t *testing.T) {
	t.Setenv("VESSEL_MCP_CONFIG", `{"edges":{"web":{"target":"http://web:8000/mcp","deny":["delete_all"]}}}`)
	cfg, err := mcpGatewayConfigFromEnv()
	if err != nil {
		t.Fatalf("mcpGatewayConfigFromEnv: %v", err)
	}
	edge, ok := cfg.Edges["web"]
	if !ok {
		t.Fatalf("edge 'web' missing: %+v", cfg)
	}
	if edge.Target != "http://web:8000/mcp" || len(edge.Deny) != 1 || edge.Deny[0] != "delete_all" {
		t.Errorf("parsed edge = %+v", edge)
	}
}

func TestMCPGatewayConfigFromEnv_RejectsGarbage(t *testing.T) {
	t.Setenv("VESSEL_MCP_CONFIG", "not json")
	if _, err := mcpGatewayConfigFromEnv(); err == nil || !strings.Contains(err.Error(), "parsing") {
		t.Fatalf("expected a parse error, got %v", err)
	}
}
