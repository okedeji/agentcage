package runtime

import (
	"context"

	"github.com/okedeji/agentcage/internal/mcpgateway"
)

// mcpGatewayContainer is the MCP gateway's container name for a run, where it
// logs the sub-agent calls the daemon reads at finish. It mirrors the name the
// planner gives the gateway.
func mcpGatewayContainer(runID string) string { return runID + "-gw" }

// RunSubagentCalls reads a run's sub-agent call metadata off the MCP gateway log,
// for the daemon to add sub-agent spans to the run's trace. ok reports whether
// the gateway log was readable; a single-agent run with no MCP gateway comes back
// empty. Read before teardown removes the gateway.
func RunSubagentCalls(ctx context.Context, runID string) ([]mcpgateway.SubCallEvent, bool) {
	p, err := DefaultProvisioner()
	if err != nil {
		return nil, false
	}
	defer func() { _ = p.Close() }()
	log, ok := readGatewayLog(ctx, p, mcpGatewayContainer(runID))
	if !ok {
		return nil, false
	}
	return mcpgateway.ParseSubCallLines(log), true
}

// RunSubagentReplay reads a recording run's sub-agent call payloads off the MCP
// gateway log, for the daemon to add sub-agent events to the .replay artifact.
func RunSubagentReplay(ctx context.Context, runID string) ([]mcpgateway.SubCallRecord, bool) {
	p, err := DefaultProvisioner()
	if err != nil {
		return nil, false
	}
	defer func() { _ = p.Close() }()
	log, ok := readGatewayLog(ctx, p, mcpGatewayContainer(runID))
	if !ok {
		return nil, false
	}
	return mcpgateway.ParseSubReplayLines(log), true
}
