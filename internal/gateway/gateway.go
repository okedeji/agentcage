// Package gateway is the in-run MCP gateway: it routes a parent agent's
// calls to each USES sub-agent and rejects calls to denied tools. It runs
// as a container on the per-run network; the parent's
// AGENTCAGE_USES_<NAME>_URL values point at it, one path per USES edge.
//
// It is a transparent MCP-over-HTTP reverse proxy with one added check:
// before forwarding a tools/call, it consults the edge's deny list and
// refuses denied tools with a JSON-RPC error. The MCP handshake,
// tools/list, and streaming all pass through untouched. It does route and
// deny, nothing more: no auth, rate limits, or TLS, because it sits on a
// private per-run network whose only caller is the trusted parent.
package gateway

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
)

// Edge is one routing entry: where a USES sub-agent's MCP server lives and
// which of its tools the caller may not invoke.
type Edge struct {
	Target string   `json:"target"` // sub-agent MCP URL, e.g. http://web-search:8000/mcp
	Deny   []string `json:"deny,omitempty"`
}

// Config is the gateway's routing table: the first path segment of an
// injected URL maps to its edge. The runtime builds one entry per USES
// edge across the whole dependency tree.
type Config struct {
	Edges map[string]Edge `json:"edges"`
}

// Handler routes /<edge>/... to the edge's target, rejecting a tools/call
// to a denied tool with a JSON-RPC error and forwarding everything else.
func Handler(cfg Config) http.Handler {
	proxies := make(map[string]*httputil.ReverseProxy, len(cfg.Edges))
	deny := make(map[string]map[string]bool, len(cfg.Edges))
	for id, edge := range cfg.Edges {
		target, err := url.Parse(edge.Target)
		if err != nil {
			continue
		}
		proxies[id] = &httputil.ReverseProxy{
			Rewrite: func(r *httputil.ProxyRequest) {
				// Forward to the sub-agent's exact endpoint, dropping the
				// /<edge> prefix the parent addressed us by.
				r.Out.URL.Scheme = target.Scheme
				r.Out.URL.Host = target.Host
				r.Out.URL.Path = target.Path
				r.Out.Host = target.Host
			},
			// Stream streamable-HTTP SSE events back immediately.
			FlushInterval: -1,
		}
		deny[id] = denySet(edge.Deny)
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := firstSegment(r.URL.Path)
		proxy, ok := proxies[id]
		if !ok {
			http.Error(w, "unknown gateway edge: "+id, http.StatusNotFound)
			return
		}
		// Only POST carries a JSON-RPC request body to inspect; GET (SSE)
		// and DELETE (session close) forward untouched.
		if r.Method == http.MethodPost {
			body, err := io.ReadAll(r.Body)
			_ = r.Body.Close()
			if err != nil {
				http.Error(w, "reading request body", http.StatusBadRequest)
				return
			}
			if tool, denied := deniedCall(body, deny[id]); denied {
				writeDenied(w, body, tool)
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(body))
			r.ContentLength = int64(len(body))
		}
		proxy.ServeHTTP(w, r)
	})
}

// deniedCall reports whether body is a tools/call to a denied tool. A body
// that is not a parseable tools/call is not denied: the gateway only
// blocks calls it positively recognizes as targeting a denied tool. (Batch
// JSON-RPC arrays are not inspected; MCP clients send one request per POST.)
func deniedCall(body []byte, deny map[string]bool) (string, bool) {
	if len(deny) == 0 {
		return "", false
	}
	var req struct {
		Method string `json:"method"`
		Params struct {
			Name string `json:"name"`
		} `json:"params"`
	}
	if json.Unmarshal(body, &req) != nil {
		return "", false
	}
	if req.Method == "tools/call" && deny[req.Params.Name] {
		return req.Params.Name, true
	}
	return "", false
}

// writeDenied answers a denied call with a JSON-RPC error carrying the
// request's id, so the caller's MCP client surfaces it as a normal tool
// error rather than a transport failure.
func writeDenied(w http.ResponseWriter, body []byte, tool string) {
	var req struct {
		ID json.RawMessage `json:"id"`
	}
	_ = json.Unmarshal(body, &req)
	id := req.ID
	if len(id) == 0 {
		id = json.RawMessage("null")
	}

	resp := struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Error   struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}{JSONRPC: "2.0", ID: id}
	resp.Error.Code = -32003
	resp.Error.Message = "tool " + tool + " denied by the gateway"

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

func firstSegment(path string) string {
	path = strings.TrimPrefix(path, "/")
	if i := strings.IndexByte(path, '/'); i >= 0 {
		return path[:i]
	}
	return path
}

func denySet(names []string) map[string]bool {
	if len(names) == 0 {
		return nil
	}
	m := make(map[string]bool, len(names))
	for _, n := range names {
		m[n] = true
	}
	return m
}
