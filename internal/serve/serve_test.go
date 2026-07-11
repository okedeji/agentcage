package serve

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/okedeji/mcpvessel/internal/mcp"
)

// staticAgent returns the same target for every session; no instance manager.
func staticAgent(addr string, tools []mcp.Tool, call func(context.Context, string, map[string]any) (string, error), bind func(mcp.ElicitHandler) func()) Agent {
	return Agent{
		Address: addr,
		Tools:   tools,
		Resolve: func(context.Context, string) (Target, func(), error) {
			return Target{Call: call, BindElicit: bind}, func() {}, nil
		},
	}
}

func TestHandler_ListsAndCallsPublicTools(t *testing.T) {
	var called string
	agent := staticAgent("researcher",
		[]mcp.Tool{{Name: "search", Description: "search the web", Schema: map[string]any{"type": "object"}}},
		func(_ context.Context, tool string, args map[string]any) (string, error) {
			called = tool
			return "q=" + args["q"].(string), nil
		}, nil)

	srv := httptest.NewServer(Handler([]Agent{agent}, nil))
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
	agent := staticAgent("researcher",
		[]mcp.Tool{{Name: "search", Schema: map[string]any{"type": "object"}}},
		func(_ context.Context, tool string, _ map[string]any) (string, error) {
			return "should not run for " + tool, nil
		}, nil)

	srv := httptest.NewServer(Handler([]Agent{agent}, nil))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client, err := mcp.ConnectHTTP(ctx, srv.URL+"/agents/researcher/mcp")
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer func() { _ = client.Close() }()

	// rerank is private, never registered; the call must be rejected.
	if _, err := client.CallTool(ctx, "rerank", nil); err == nil {
		t.Fatal("front door dispatched a call to an unregistered private tool")
	}
}

// askingAgent's tool asks the caller a question mid-call through its bound
// answer channel, mirroring the daemon's session.BindElicit.
func askingAgent() Agent {
	var bound mcp.ElicitHandler
	return staticAgent("asker",
		[]mcp.Tool{{Name: "deploy", Schema: map[string]any{"type": "object"}}},
		func(ctx context.Context, _ string, _ map[string]any) (string, error) {
			res, err := bound(ctx, &mcp.ElicitRequest{Message: "prod or staging?"})
			if err != nil {
				return "", err
			}
			where, _ := res.Content["env"].(string)
			return "deploying to " + where, nil
		},
		func(h mcp.ElicitHandler) func() {
			bound = h
			return func() { bound = nil }
		})
}

func TestHandler_ElicitsThroughCaller(t *testing.T) {
	srv := httptest.NewServer(Handler([]Agent{askingAgent()}, nil))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client, err := mcp.ConnectHTTP(ctx, srv.URL+"/agents/asker/mcp", mcp.WithElicitation(
		func(_ context.Context, q *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
			if !strings.Contains(q.Message, "prod or staging") {
				t.Errorf("caller saw question %q", q.Message)
			}
			return &mcp.ElicitResult{Action: "accept", Content: map[string]any{"env": "staging"}}, nil
		}))
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer func() { _ = client.Close() }()

	out, err := client.CallTool(ctx, "deploy", nil)
	if err != nil {
		t.Fatalf("call: %v", err)
	}
	if !strings.Contains(out, "staging") {
		t.Errorf("result = %q, want the caller's answer folded in", out)
	}
}

func TestHandler_ElicitFailsClosedWithoutCallerSupport(t *testing.T) {
	srv := httptest.NewServer(Handler([]Agent{askingAgent()}, nil))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client, err := mcp.ConnectHTTP(ctx, srv.URL+"/agents/asker/mcp")
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer func() { _ = client.Close() }()

	if _, err := client.CallTool(ctx, "deploy", nil); err == nil {
		t.Fatal("expected the call to fail closed when the caller cannot answer")
	}
}

// Each call blocks on a barrier that opens only once both are in flight;
// serialized dispatch would never open it and the calls would time out.
func TestHandler_ConcurrentClientsDoNotSerialize(t *testing.T) {
	const clients = 2
	var inFlight int32
	barrier := make(chan struct{})
	agent := Agent{
		Address: "worker",
		Tools:   []mcp.Tool{{Name: "work", Schema: map[string]any{"type": "object"}}},
		Resolve: func(_ context.Context, sessionID string) (Target, func(), error) {
			return Target{Call: func(ctx context.Context, _ string, _ map[string]any) (string, error) {
				if atomic.AddInt32(&inFlight, 1) == clients {
					close(barrier)
				}
				select {
				case <-barrier:
					return sessionID, nil
				case <-ctx.Done():
					return "", ctx.Err()
				}
			}}, func() {}, nil
		},
	}

	srv := httptest.NewServer(Handler([]Agent{agent}, nil))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	results := make([]string, clients)
	errs := make([]error, clients)
	var wg sync.WaitGroup
	for i := 0; i < clients; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			client, err := mcp.ConnectHTTP(ctx, srv.URL+"/agents/worker/mcp")
			if err != nil {
				errs[i] = err
				return
			}
			defer func() { _ = client.Close() }()
			results[i], errs[i] = client.CallTool(ctx, "work", nil)
		}(i)
	}
	wg.Wait()

	for i := 0; i < clients; i++ {
		if errs[i] != nil {
			t.Fatalf("client %d failed (serialized?): %v", i, errs[i])
		}
	}
	if results[0] == results[1] {
		t.Errorf("both clients resolved to the same session id %q, want distinct", results[0])
	}
}

func TestHandler_SeparateEndpointPerAgent(t *testing.T) {
	mk := func(addr, tool string) Agent {
		return staticAgent(addr,
			[]mcp.Tool{{Name: tool, Schema: map[string]any{"type": "object"}}},
			func(context.Context, string, map[string]any) (string, error) { return addr, nil }, nil)
	}
	srv := httptest.NewServer(Handler([]Agent{mk("researcher", "search"), mk("web-scraper", "fetch")}, nil))
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

// echoAgent answers every call with "<addr>:<tool the target saw>", proving
// which agent got the dispatch and under what name.
func echoAgent(addr string, tools ...string) Agent {
	mcpTools := make([]mcp.Tool, len(tools))
	for i, name := range tools {
		mcpTools[i] = mcp.Tool{Name: name, Schema: map[string]any{"type": "object"}}
	}
	return staticAgent(addr, mcpTools,
		func(_ context.Context, tool string, _ map[string]any) (string, error) {
			return addr + ":" + tool, nil
		}, nil)
}

func mustFlat(t *testing.T, agents []Agent) []FlatTool {
	t.Helper()
	flat, err := FlatTools(agents)
	if err != nil {
		t.Fatalf("FlatTools: %v", err)
	}
	return flat
}

func TestFlatTools_EveryNamePrefixedByAgent(t *testing.T) {
	agents := []Agent{echoAgent("github", "create_issue", "search"), echoAgent("web.scraper", "search")}
	flat := mustFlat(t, agents)
	got := map[string]bool{}
	for _, ft := range flat {
		got[ft.Name] = true
	}
	// Every name carries its agent's prefix (dots sanitized for MCP tool
	// names) so adding a bundle can never rename an existing tool.
	for _, want := range []string{"github_create_issue", "github_search", "web_scraper_search"} {
		if !got[want] {
			t.Errorf("flat names = %v, missing %q", got, want)
		}
	}
	if len(flat) != 3 {
		t.Errorf("flat has %d tools, want 3", len(flat))
	}
}

func TestFlatTools_SurvivingCollisionIsAnError(t *testing.T) {
	// Two addresses that sanitize identically produce the same prefixed name.
	agents := []Agent{
		echoAgent("web.scraper", "search"),
		echoAgent("web_scraper", "search"),
	}
	if _, err := FlatTools(agents); err == nil {
		t.Fatal("FlatTools accepted a collision that survived prefixing")
	}
}

func TestHandler_FlatEndpointMergesAgents(t *testing.T) {
	agents := []Agent{echoAgent("github", "create_issue"), echoAgent("time", "now")}
	srv := httptest.NewServer(Handler(agents, mustFlat(t, agents)))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client, err := mcp.ConnectHTTP(ctx, srv.URL+FlatPath)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer func() { _ = client.Close() }()

	tools, err := client.ListTools(ctx)
	if err != nil {
		t.Fatalf("list tools: %v", err)
	}
	if len(tools) != 2 {
		t.Fatalf("flat endpoint lists %v, want both agents' tools", tools)
	}

	out, err := client.CallTool(ctx, "time_now", nil)
	if err != nil {
		t.Fatalf("call: %v", err)
	}
	if out != "time:now" {
		t.Errorf("call dispatched to %q, want time:now", out)
	}
}

func TestHandler_FlatEndpointForwardsOriginalNameOnCollision(t *testing.T) {
	agents := []Agent{echoAgent("github", "search"), echoAgent("time", "search")}
	srv := httptest.NewServer(Handler(agents, mustFlat(t, agents)))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client, err := mcp.ConnectHTTP(ctx, srv.URL+FlatPath)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer func() { _ = client.Close() }()

	// The prefixed name routes to the right agent, which must see the tool's
	// original name, not the prefixed one.
	out, err := client.CallTool(ctx, "time_search", nil)
	if err != nil {
		t.Fatalf("call: %v", err)
	}
	if out != "time:search" {
		t.Errorf("call dispatched to %q, want time:search (original name)", out)
	}
}

// echoArgsAgent returns an agent whose tool calls echo "<tool> <json-args>", so
// a test can assert the tool routed to and the args it received.
func echoArgsAgent(addr, main string, tools ...string) Agent {
	mcpTools := make([]mcp.Tool, len(tools))
	for i, name := range tools {
		mcpTools[i] = mcp.Tool{Name: name, Schema: map[string]any{"type": "object"}}
	}
	return Agent{
		Address: addr,
		Main:    main,
		Tools:   mcpTools,
		Resolve: func(context.Context, string) (Target, func(), error) {
			return Target{Call: func(_ context.Context, tool string, args map[string]any) (string, error) {
				b, _ := json.Marshal(args)
				return tool + " " + string(b), nil
			}}, func() {}, nil
		},
	}
}

type httpResp struct {
	code int
	body string
}

func postJSON(t *testing.T, url, body string) httpResp {
	t.Helper()
	resp, err := http.Post(url, "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("post %s: %v", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return httpResp{code: resp.StatusCode, body: string(b)}
}

func (r httpResp) result(t *testing.T) string {
	t.Helper()
	var out struct {
		Result string `json:"result"`
	}
	if err := json.Unmarshal([]byte(r.body), &out); err != nil {
		t.Fatalf("decoding result from %q: %v", r.body, err)
	}
	return out.Result
}

func TestHTTP_CallTool(t *testing.T) {
	srv := httptest.NewServer(Handler([]Agent{echoArgsAgent("time", "", "get_current_time")}, nil))
	defer srv.Close()

	res := postJSON(t, srv.URL+"/agents/time/tools/get_current_time", `{"timezone":"Africa/Lagos"}`)
	if res.code != http.StatusOK {
		t.Fatalf("status %d, body %s", res.code, res.body)
	}
	got := res.result(t)
	if !strings.Contains(got, "get_current_time") || !strings.Contains(got, "Africa/Lagos") {
		t.Errorf("result = %q, want the tool name and the argument echoed", got)
	}
}

func TestHTTP_Prompt(t *testing.T) {
	srv := httptest.NewServer(Handler([]Agent{echoArgsAgent("assistant", "respond", "respond")}, nil))
	defer srv.Close()

	res := postJSON(t, srv.URL+"/agents/assistant", `{"prompt":"what time is it in Lagos"}`)
	if res.code != http.StatusOK {
		t.Fatalf("status %d, body %s", res.code, res.body)
	}
	got := res.result(t)
	if !strings.Contains(got, "respond") || !strings.Contains(got, "what time is it in Lagos") || !strings.Contains(got, "user") {
		t.Errorf("result = %q, want the prompt wrapped as a user message to respond", got)
	}
}

func TestHTTP_FlatCallTool(t *testing.T) {
	agents := []Agent{echoArgsAgent("github", "", "search"), echoArgsAgent("time", "", "now")}
	srv := httptest.NewServer(Handler(agents, mustFlat(t, agents)))
	defer srv.Close()

	res := postJSON(t, srv.URL+"/tools/time_now", `{}`)
	if res.code != http.StatusOK {
		t.Fatalf("status %d, body %s", res.code, res.body)
	}
	if !strings.Contains(res.result(t), "now") {
		t.Errorf("result = %q, want the time agent's now tool", res.result(t))
	}
}

func TestHTTP_UnknownToolIs404(t *testing.T) {
	srv := httptest.NewServer(Handler([]Agent{echoArgsAgent("time", "", "now")}, nil))
	defer srv.Close()

	res := postJSON(t, srv.URL+"/agents/time/tools/secret_admin", `{}`)
	if res.code != http.StatusNotFound {
		t.Errorf("status = %d, want 404 for a non-public tool", res.code)
	}
}

func TestHTTP_NoPromptEndpointWithoutMain(t *testing.T) {
	srv := httptest.NewServer(Handler([]Agent{echoArgsAgent("time", "", "now")}, nil))
	defer srv.Close()

	res := postJSON(t, srv.URL+"/agents/time", `{"prompt":"hi"}`)
	if res.code == http.StatusOK {
		t.Errorf("prompt endpoint answered for an agent with no MAIN (status %d)", res.code)
	}
}
