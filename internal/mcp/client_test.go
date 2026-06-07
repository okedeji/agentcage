package mcp

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

// testServer starts an in-memory MCP server on one end of a net.Pipe,
// hands the other end to a Connect-driven Client, and returns both.
// The server is configured by the addTools callback; passing nil
// produces a server with no tools registered.
//
// Cleanup is registered with t.Cleanup so callers do not have to defer.
func testServer(t *testing.T, addTools func(s *mcpsdk.Server)) (*Client, *mcpsdk.Server) {
	t.Helper()

	srvConn, cliConn := net.Pipe()
	t.Cleanup(func() {
		_ = srvConn.Close()
		_ = cliConn.Close()
	})

	server := mcpsdk.NewServer(&mcpsdk.Implementation{
		Name:    "agentcage-test-server",
		Version: "0.0.0",
	}, nil)
	if addTools != nil {
		addTools(server)
	}

	serverCtx, cancelServer := context.WithCancel(context.Background())
	t.Cleanup(cancelServer)

	go func() {
		_ = server.Run(serverCtx, &mcpsdk.IOTransport{
			Reader: srvConn,
			Writer: srvConn,
		})
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client, err := Connect(ctx, cliConn, cliConn)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client, server
}

func TestConnect_HandshakeSucceeds(t *testing.T) {
	_, _ = testServer(t, nil)
	// Reaching here means the MCP initialize round-trip completed.
}

func TestListTools_EmptyServer(t *testing.T) {
	client, _ := testServer(t, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	tools, err := client.ListTools(ctx)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	if len(tools) != 0 {
		t.Errorf("ListTools = %d tools, want 0 (got %+v)", len(tools), tools)
	}
}

func TestListTools_ReturnsRegisteredTools(t *testing.T) {
	client, _ := testServer(t, func(s *mcpsdk.Server) {
		registerEchoTool(s)
		registerGreetTool(s)
	})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	tools, err := client.ListTools(ctx)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	names := map[string]string{}
	for _, tool := range tools {
		names[tool.Name] = tool.Description
	}
	if names["echo"] != "echoes its input back" {
		t.Errorf("missing echo or wrong description: %+v", names)
	}
	if names["greet"] != "greets by name" {
		t.Errorf("missing greet or wrong description: %+v", names)
	}
}

func TestCallTool_ReturnsTextContent(t *testing.T) {
	client, _ := testServer(t, registerEchoTool)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	got, err := client.CallTool(ctx, "echo", map[string]any{"message": "hello"})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if got != "hello" {
		t.Errorf("CallTool echo = %q, want %q", got, "hello")
	}
}

func TestCallTool_UnknownTool(t *testing.T) {
	client, _ := testServer(t, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := client.CallTool(ctx, "nonexistent", nil)
	if err == nil {
		t.Fatalf("expected error for unknown tool, got nil")
	}
	// Error must name the tool so the operator can see which call failed.
	if !errorContains(err, "nonexistent") {
		t.Errorf("error does not name the tool: %v", err)
	}
}

func TestCallTool_ToolReturnsIsErrorResult(t *testing.T) {
	client, _ := testServer(t, registerFailingTool)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := client.CallTool(ctx, "fail", nil)
	if err == nil {
		t.Fatalf("expected error from failing tool, got nil")
	}
	if !errorContains(err, "fail") {
		t.Errorf("error does not name the tool: %v", err)
	}
}

func TestClose_IsSafeOnNil(t *testing.T) {
	var c *Client
	if err := c.Close(); err != nil {
		t.Errorf("Close on nil receiver returned: %v", err)
	}
	c = &Client{}
	if err := c.Close(); err != nil {
		t.Errorf("Close on zero struct returned: %v", err)
	}
}

func TestFirstText_PicksFirstTextBlock(t *testing.T) {
	blocks := []mcpsdk.Content{
		&mcpsdk.TextContent{Text: "first"},
		&mcpsdk.TextContent{Text: "second"},
	}
	if got := firstText(blocks); got != "first" {
		t.Errorf("firstText = %q, want %q", got, "first")
	}
}

func TestFirstText_EmptyWhenNoText(t *testing.T) {
	if got := firstText(nil); got != "" {
		t.Errorf("firstText(nil) = %q, want empty", got)
	}
	if got := firstText([]mcpsdk.Content{}); got != "" {
		t.Errorf("firstText(empty slice) = %q, want empty", got)
	}
}

// ----- test fixtures: tools the in-memory server exposes -----

type echoInput struct {
	Message string `json:"message"`
}
type echoOutput struct {
	Echoed string `json:"echoed"`
}

func registerEchoTool(s *mcpsdk.Server) {
	mcpsdk.AddTool(s, &mcpsdk.Tool{
		Name:        "echo",
		Description: "echoes its input back",
	}, func(_ context.Context, _ *mcpsdk.CallToolRequest, in echoInput) (*mcpsdk.CallToolResult, echoOutput, error) {
		return &mcpsdk.CallToolResult{
			Content: []mcpsdk.Content{&mcpsdk.TextContent{Text: in.Message}},
		}, echoOutput{Echoed: in.Message}, nil
	})
}

type greetInput struct {
	Name string `json:"name"`
}
type greetOutput struct {
	Greeting string `json:"greeting"`
}

func registerGreetTool(s *mcpsdk.Server) {
	mcpsdk.AddTool(s, &mcpsdk.Tool{
		Name:        "greet",
		Description: "greets by name",
	}, func(_ context.Context, _ *mcpsdk.CallToolRequest, in greetInput) (*mcpsdk.CallToolResult, greetOutput, error) {
		text := "hello " + in.Name
		return &mcpsdk.CallToolResult{
			Content: []mcpsdk.Content{&mcpsdk.TextContent{Text: text}},
		}, greetOutput{Greeting: text}, nil
	})
}

func registerFailingTool(s *mcpsdk.Server) {
	mcpsdk.AddTool(s, &mcpsdk.Tool{
		Name:        "fail",
		Description: "always fails",
	}, func(_ context.Context, _ *mcpsdk.CallToolRequest, _ struct{}) (*mcpsdk.CallToolResult, struct{}, error) {
		return nil, struct{}{}, errors.New("intentional failure")
	})
}

// errorContains is a thin shim around strings.Contains for use in
// table-driven error-message assertions.
func errorContains(err error, needle string) bool {
	return err != nil && contains(err.Error(), needle)
}

func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
