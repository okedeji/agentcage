package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"github.com/spf13/cobra"

	"github.com/okedeji/agentcage/internal/env"
	"github.com/okedeji/agentcage/internal/mcpgateway"
)

// newMCPGatewayCmd runs the in-run MCP gateway. It is hidden: the runtime
// starts it inside the gateway container, not operators. Its routing table
// and listen address arrive as environment the runtime injects.
func newMCPGatewayCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:    "mcp-gateway",
		Short:  "Run the in-run MCP gateway (internal)",
		Hidden: true,
		Args:   cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := mcpGatewayConfigFromEnv()
			if err != nil {
				return err
			}
			addr := os.Getenv(env.MCPAddr)
			if addr == "" {
				addr = ":" + env.DefaultMCPGatewayPort
			}
			srv := &http.Server{Addr: addr, Handler: mcpgateway.Handler(cfg)}
			return srv.ListenAndServe()
		},
	}
	return cmd
}

// mcpGatewayConfigFromEnv reads the routing table the runtime injected.
func mcpGatewayConfigFromEnv() (mcpgateway.Config, error) {
	raw := os.Getenv(env.MCPConfig)
	if raw == "" {
		return mcpgateway.Config{}, fmt.Errorf("%s is required", env.MCPConfig)
	}
	var cfg mcpgateway.Config
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		return mcpgateway.Config{}, fmt.Errorf("parsing %s: %w", env.MCPConfig, err)
	}
	return cfg, nil
}
