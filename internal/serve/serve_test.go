package serve

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/okedeji/agentcage/internal/mcp"
)

func TestHandler_ListsAndCallsPublicTools(t *testing.T) {
	var called string
	agent := Agent{
		Address: "researcher",
		Tools: []mcp.Tool{
			{Name: "search", Description: "search the web", Schema: map[string]any{"type": "object"}},
		},
		Call: func(_ context.Context, tool string, args map[string]any) (string, error) {
			called = tool
			return "q=" + args["q"].(string), nil
		},
	}

	srv := httptest.NewServer(Handler([]Agent{agent}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client, err := mcp.ConnectHTTP(ctx, srv.URL+"/agents/researcher/mcp")
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer func() { _ = client.Close() }()

	tools, err := client.ListTools(ctx)
	if err != nil {
		t.Fatalf("list tools: %v", err)
	}
	if len(tools) != 1 || tools[0].Name != "search" {
		t.Fatalf("tools = %v, want one named search", tools)
	}

	out, err := client.CallTool(ctx, "search", map[string]any{"q": "agentic memory"})
	if err != nil {
		t.Fatalf("call: %v", err)
	}
	if called != "search" {
		t.Errorf("dispatched tool = %q, want search", called)
	}
	if !strings.Contains(out, "agentic memory") {
		t.Errorf("result = %q, want it to carry the argument", out)
	}
}

func TestHandler_PrivateToolUnreachable(t *testing.T) {
	agent := Agent{
		Address: "researcher",
		Tools:   []mcp.Tool{{Name: "search", Schema: map[string]any{"type": "object"}}},
		Call: func(_ context.Context, tool string, _ map[string]any) (string, error) {
			return "should not run for " + tool, nil
		},
	}

	srv := httptest.NewServer(Handler([]Agent{agent}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client, err := mcp.ConnectHTTP(ctx, srv.URL+"/agents/researcher/mcp")
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer func() { _ = client.Close() }()

	// rerank was never registered (it is private), so the front door must reject
	// the call rather than dispatch it into the run.
	if _, err := client.CallTool(ctx, "rerank", nil); err == nil {
		t.Fatal("front door dispatched a call to an unregistered private tool")
	}
}

func TestHandler_SeparateEndpointPerAgent(t *testing.T) {
	mk := func(addr, tool string) Agent {
		return Agent{
			Address: addr,
			Tools:   []mcp.Tool{{Name: tool, Schema: map[string]any{"type": "object"}}},
			Call:    func(context.Context, string, map[string]any) (string, error) { return addr, nil },
		}
	}
	srv := httptest.NewServer(Handler([]Agent{mk("researcher", "search"), mk("web-scraper", "fetch")}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client, err := mcp.ConnectHTTP(ctx, srv.URL+"/agents/web-scraper/mcp")
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer func() { _ = client.Close() }()

	tools, err := client.ListTools(ctx)
	if err != nil {
		t.Fatalf("list tools: %v", err)
	}
	if len(tools) != 1 || tools[0].Name != "fetch" {
		t.Fatalf("web-scraper tools = %v, want only fetch", tools)
	}
}
