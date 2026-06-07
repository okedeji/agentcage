package mcp

import (
	"context"
	"fmt"
	"io"

	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/okedeji/agentcage/internal/identity"
)

// Client is an open MCP session against a single agent process.
//
// Construct with Connect. Always Close in a defer to release the
// underlying session goroutines and stream readers.
type Client struct {
	session *mcpsdk.ClientSession
}

// Connect establishes an MCP session over the given stdio pair.
//
// `reader` is what we read agent responses from (the agent's stdout).
// `writer` is what we send agent requests to (the agent's stdin).
// Both are wrapped with io.NopCloser before reaching the SDK; the
// caller owns the lifecycle of the underlying streams.
//
// The MCP handshake (initialize) runs as part of Connect; by the time
// it returns, the agent has reported its protocol version and is ready
// for tool calls.
func Connect(ctx context.Context, reader io.Reader, writer io.Writer) (*Client, error) {
	c := mcpsdk.NewClient(&mcpsdk.Implementation{
		Name:    identity.Name,
		Version: identity.Version,
	}, nil)
	session, err := c.Connect(ctx, &mcpsdk.IOTransport{
		Reader: io.NopCloser(reader),
		Writer: nopWriteCloser{writer},
	}, nil)
	if err != nil {
		return nil, fmt.Errorf("mcp connect: %w", err)
	}
	return &Client{session: session}, nil
}

// nopWriteCloser adapts an io.Writer into an io.WriteCloser whose
// Close is a no-op, mirroring io.NopCloser for readers.
type nopWriteCloser struct{ io.Writer }

func (nopWriteCloser) Close() error { return nil }

// Close ends the session. Safe to call once; subsequent calls return
// the original error from the SDK.
func (c *Client) Close() error {
	if c == nil || c.session == nil {
		return nil
	}
	return c.session.Close()
}

// Tool is the agentcage-shaped view of one tool the agent exposes. The
// SDK's *mcpsdk.Tool carries a JSON Schema we do not always want to
// surface; this struct keeps the surface narrow.
type Tool struct {
	Name        string
	Description string
}

// ListTools returns every tool the connected agent advertises. Used by
// the CLI to look up the default tool's name when the operator did not
// pass --tool explicitly. Does not paginate; v0 agents are expected to
// expose a small handful of tools.
func (c *Client) ListTools(ctx context.Context) ([]Tool, error) {
	res, err := c.session.ListTools(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("mcp tools/list: %w", err)
	}
	out := make([]Tool, 0, len(res.Tools))
	for _, t := range res.Tools {
		out = append(out, Tool{
			Name:        t.Name,
			Description: t.Description,
		})
	}
	return out, nil
}

// CallTool invokes name with the given arguments and returns the text
// content of the first text block in the response. Non-text content
// (images, embedded resources) is ignored at this layer; if a use case
// needs it we add a method that returns the structured CallToolResult.
//
// If the tool returned an error (CallToolResult.IsError or any error
// embedded in the result), CallTool returns it wrapped with the name.
func (c *Client) CallTool(ctx context.Context, name string, args any) (string, error) {
	res, err := c.session.CallTool(ctx, &mcpsdk.CallToolParams{
		Name:      name,
		Arguments: args,
	})
	if err != nil {
		return "", fmt.Errorf("mcp tools/call %s: %w", name, err)
	}
	if res.IsError {
		return "", fmt.Errorf("mcp tools/call %s: tool returned an error: %s", name, firstText(res.Content))
	}
	return firstText(res.Content), nil
}

// firstText returns the text of the first TextContent block in blocks,
// or empty string if none is present.
func firstText(blocks []mcpsdk.Content) string {
	for _, c := range blocks {
		if t, ok := c.(*mcpsdk.TextContent); ok {
			return t.Text
		}
	}
	return ""
}
