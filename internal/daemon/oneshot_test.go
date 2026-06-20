package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestRunRequest_RedactsSecrets(t *testing.T) {
	req := RunRequest{
		Ref:     "@me/x:0.1",
		Tool:    "respond",
		Env:     map[string]string{"REGION": "eu"},
		Secrets: map[string]string{"OPENAI_API_KEY": "sk-supersecret"},
	}
	for _, s := range []string{req.String(), req.GoString()} {
		if strings.Contains(s, "sk-supersecret") {
			t.Errorf("rendered request leaks a secret value: %q", s)
		}
		if strings.Contains(s, "eu") {
			t.Errorf("rendered request leaks an env value: %q", s)
		}
		if !strings.Contains(s, "@me/x:0.1") {
			t.Errorf("rendered request should still name the ref: %q", s)
		}
	}
}

// rewriteTransport points a Client built for a Unix socket at an httptest
// server instead, so RunOnce's streaming can be driven without booting a cage.
type rewriteTransport struct{ base *url.URL }

func (rt rewriteTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r.URL.Scheme = rt.base.Scheme
	r.URL.Host = rt.base.Host
	return http.DefaultTransport.RoundTrip(r)
}

func clientFor(t *testing.T, srv *httptest.Server) *Client {
	t.Helper()
	base, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse server url: %v", err)
	}
	return &Client{http: &http.Client{Transport: rewriteTransport{base}}}
}

func TestRunOnce_StreamsLogsThenResult(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		enc := json.NewEncoder(w)
		_ = enc.Encode(runFrame{Type: "log", Data: "building...\n"})
		_ = enc.Encode(runFrame{Type: "log", Data: "reasoning...\n"})
		_ = enc.Encode(runFrame{Type: "result", Data: "the answer"})
	}))
	defer srv.Close()

	var logs bytes.Buffer
	result, err := clientFor(t, srv).RunOnce(context.Background(), RunRequest{Ref: "x", Tool: "respond"}, &logs)
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if result != "the answer" {
		t.Errorf("result = %q, want %q", result, "the answer")
	}
	if got := logs.String(); got != "building...\nreasoning...\n" {
		t.Errorf("logs = %q, want the two streamed log lines", got)
	}
}

func TestRunOnce_ErrorFrameBecomesError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(runFrame{Type: "error", Data: "bundle has no MAIN"})
	}))
	defer srv.Close()

	_, err := clientFor(t, srv).RunOnce(context.Background(), RunRequest{Ref: "x", Tool: "respond"}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "no MAIN") {
		t.Fatalf("err = %v, want it to carry the error frame", err)
	}
}

func TestRunOnce_UnreachableDaemon(t *testing.T) {
	_, err := Dial("/nonexistent/agentcage.sock").RunOnce(context.Background(), RunRequest{Ref: "x", Tool: "respond"}, &bytes.Buffer{})
	var unreachable *Unreachable
	if err == nil || !errors.As(err, &unreachable) {
		t.Fatalf("err = %v, want an *Unreachable", err)
	}
}

func TestHandleRun_RequiresRefAndTool(t *testing.T) {
	d := New()
	for _, body := range []string{`{}`, `{"ref":"x"}`} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/run", strings.NewReader(body))
		d.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("body %s: status = %d, want 400", body, rec.Code)
		}
	}
}
