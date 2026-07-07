package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"syscall"

	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/spf13/cobra"

	"github.com/okedeji/agentcage/internal/env"
	"github.com/okedeji/agentcage/internal/identity"
	"github.com/okedeji/agentcage/internal/wrap"
)

// newMCPBridgeCmd builds the bridge that lets an imported stdio-only MCP server
// serve as a USES sub-agent. An imported server speaks MCP over stdio, which is
// all a root cage needs; a sub-agent is reached over streamable HTTP on the
// address in AGENTCAGE_SERVE_HTTP. The bridge is the wrapped tool collection's
// ENTRYPOINT and closes that gap: as a sub-agent it serves HTTP and forwards
// every tool to the inner stdio server it spawns; as a root it execs the inner
// server so the bridge never sits in the stdio path the daemon drives.
//
// It reuses agentcage's own MCP stack (the go-sdk client and streamable-HTTP
// server), so it is one static binary that works in any base image, node or
// python or otherwise, with no language runtime of its own.
func newMCPBridgeCmd() *cobra.Command {
	return &cobra.Command{
		Use:    wrap.BridgeSubcommand + " -- SERVER [ARG...]",
		Short:  "Serve an imported stdio MCP server over HTTP so it can be a USES sub-agent",
		Hidden: true,
		// The inner server carries its own flags (npx -y, ...). Parse none of them
		// here; everything after `--` is the server command, forwarded verbatim.
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			inner, err := innerServerCommand(args)
			if err != nil {
				return err
			}
			bind := os.Getenv(env.ServeHTTP)
			if bind == "" {
				return execInner(inner)
			}
			return serveBridge(cmd.Context(), bind, inner)
		},
	}
}

// innerServerCommand returns the wrapped server's command, the tokens after the
// `--` the ENTRYPOINT passes.
func innerServerCommand(args []string) ([]string, error) {
	for i, a := range args {
		if a == "--" {
			if i+1 >= len(args) {
				break
			}
			return args[i+1:], nil
		}
	}
	return nil, fmt.Errorf("mcp-bridge: expected '-- <server command>'")
}

// execInner replaces the bridge process with the inner server. As a root the
// daemon drives the cage over stdio, so the bridge must not sit in that path; it
// hands its own stdin and stdout to the inner server wholesale.
func execInner(inner []string) error {
	path, err := exec.LookPath(inner[0])
	if err != nil {
		return fmt.Errorf("mcp-bridge: locating %s: %w", inner[0], err)
	}
	if err := syscall.Exec(path, inner, os.Environ()); err != nil {
		return fmt.Errorf("mcp-bridge: exec %s: %w", inner[0], err)
	}
	return nil
}

// serveBridge spawns the inner stdio server, mirrors its tools onto an HTTP MCP
// server, and serves that on bind. Every tools/call is forwarded to the inner
// session unchanged, so the sub-agent presents exactly the tools, and the same
// results, the imported server does.
func serveBridge(ctx context.Context, bind string, inner []string) error {
	client := mcpsdk.NewClient(&mcpsdk.Implementation{Name: identity.Name, Version: identity.Version}, nil)
	proc := exec.Command(inner[0], inner[1:]...)
	proc.Stderr = os.Stderr
	session, err := client.Connect(ctx, &mcpsdk.CommandTransport{Command: proc}, nil)
	if err != nil {
		return fmt.Errorf("mcp-bridge: connecting to %s: %w", inner[0], err)
	}
	defer func() { _ = session.Close() }()

	tools, err := session.ListTools(ctx, nil)
	if err != nil {
		return fmt.Errorf("mcp-bridge: listing tools from %s: %w", inner[0], err)
	}

	server := mcpsdk.NewServer(&mcpsdk.Implementation{Name: identity.Name, Version: identity.Version}, nil)
	for _, t := range tools.Tools {
		name := t.Name
		server.AddTool(
			&mcpsdk.Tool{Name: t.Name, Description: t.Description, InputSchema: t.InputSchema},
			func(ctx context.Context, req *mcpsdk.CallToolRequest) (*mcpsdk.CallToolResult, error) {
				return session.CallTool(ctx, &mcpsdk.CallToolParams{Name: name, Arguments: req.Params.Arguments})
			},
		)
	}

	// The per-run gateway on a private network is the trust boundary in front of
	// this port, and it forwards its own Host header; the SDK's DNS-rebinding
	// guard would reject that mismatch. Nothing outside the run can reach the
	// port, so turn the guard off rather than let it 403 the gateway.
	handler := mcpsdk.NewStreamableHTTPHandler(
		func(*http.Request) *mcpsdk.Server { return server },
		&mcpsdk.StreamableHTTPOptions{DisableLocalhostProtection: true},
	)
	mux := http.NewServeMux()
	mux.Handle("/mcp", handler)
	mux.Handle("/mcp/", handler)
	return (&http.Server{Addr: bind, Handler: mux}).ListenAndServe()
}
