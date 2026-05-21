package enforcement

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestJudgeServer(handler http.HandlerFunc) (*httptest.Server, *JudgeClient) {
	srv := httptest.NewServer(handler)
	client := NewJudgeClient(srv.URL, 0.7, "test-key", 5*time.Second)
	return srv, client
}

// respondToolCall writes an OpenAI-style chat completion that contains
// a single tool_call to `submit_judgment` with the given arguments
// and usage. Mirrors what a passthrough webhook in front of OpenAI
// would return.
func respondToolCall(w http.ResponseWriter, safe bool, confidence float64, reason string, usage map[string]int64) {
	args, _ := json.Marshal(map[string]any{
		"safe":       safe,
		"confidence": confidence,
		"reason":     reason,
	})
	resp := map[string]any{
		"choices": []map[string]any{{
			"message": map[string]any{
				"tool_calls": []map[string]any{{
					"id":   "call_1",
					"type": "function",
					"function": map[string]any{
						"name":      "submit_judgment",
						"arguments": string(args),
					},
				}},
			},
		}},
	}
	if usage != nil {
		resp["usage"] = usage
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func TestJudge_SafeHighConfidence(t *testing.T) {
	srv, client := newTestJudgeServer(func(w http.ResponseWriter, r *http.Request) {
		respondToolCall(w, true, 0.95, "benign read query", nil)
	})
	defer srv.Close()

	out, err := client.Evaluate(EvaluateInput{CageType: "discovery", VulnClass: "sqli", AssessmentID: "assess-1", Method: "POST", URL: "/api/users", Body: []byte("SELECT 1")})
	require.NoError(t, err)
	assert.Equal(t, PayloadAllow, out.Decision)
	assert.Equal(t, "benign read query", out.Reason)
}

func TestJudge_DangerousHighConfidence(t *testing.T) {
	srv, client := newTestJudgeServer(func(w http.ResponseWriter, r *http.Request) {
		respondToolCall(w, false, 0.9, "credential extraction", nil)
	})
	defer srv.Close()

	out, err := client.Evaluate(EvaluateInput{CageType: "discovery", VulnClass: "sqli", AssessmentID: "assess-1", Method: "POST", URL: "/api/users", Body: []byte("UNION SELECT password FROM users")})
	require.NoError(t, err)
	assert.Equal(t, PayloadBlock, out.Decision)
	assert.Equal(t, "credential extraction", out.Reason)
}

func TestJudge_LowConfidence_Hold(t *testing.T) {
	srv, client := newTestJudgeServer(func(w http.ResponseWriter, r *http.Request) {
		respondToolCall(w, false, 0.35, "uncertain intent", nil)
	})
	defer srv.Close()

	out, err := client.Evaluate(EvaluateInput{CageType: "discovery", VulnClass: "sqli", AssessmentID: "assess-1", Method: "POST", URL: "/api/users", Body: []byte("1' OR 1=1--")})
	require.NoError(t, err)
	assert.Equal(t, PayloadHold, out.Decision)
	assert.Equal(t, "uncertain intent", out.Reason)
}

func TestJudge_UsageSurfaced(t *testing.T) {
	srv, client := newTestJudgeServer(func(w http.ResponseWriter, r *http.Request) {
		respondToolCall(w, true, 0.9, "ok", map[string]int64{
			"prompt_tokens": 120, "completion_tokens": 35, "total_tokens": 155,
		})
	})
	defer srv.Close()

	out, err := client.Evaluate(EvaluateInput{CageType: "discovery", VulnClass: "sqli", AssessmentID: "assess-1", Method: "GET", URL: "/api"})
	require.NoError(t, err)
	assert.Equal(t, PayloadAllow, out.Decision)
	assert.Equal(t, int64(120), out.Usage.PromptTokens)
	assert.Equal(t, int64(35), out.Usage.CompletionTokens)
	assert.Equal(t, int64(155), out.Usage.TotalTokens)
}

func TestJudge_NoUsage_Zero(t *testing.T) {
	srv, client := newTestJudgeServer(func(w http.ResponseWriter, r *http.Request) {
		respondToolCall(w, true, 0.9, "ok", nil)
	})
	defer srv.Close()

	out, err := client.Evaluate(EvaluateInput{CageType: "discovery", VulnClass: "sqli", AssessmentID: "assess-1", Method: "GET", URL: "/api"})
	require.NoError(t, err)
	assert.Equal(t, int64(0), out.Usage.TotalTokens)
}

func TestJudge_Timeout_Hold(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
	}))
	defer srv.Close()

	client := NewJudgeClient(srv.URL, 0.7, "", 200*time.Millisecond)
	out, err := client.Evaluate(EvaluateInput{CageType: "discovery", VulnClass: "sqli", AssessmentID: "assess-1", Method: "GET", URL: "/api", Body: nil})
	assert.Error(t, err)
	assert.Equal(t, PayloadHold, out.Decision)
}

func TestJudge_MalformedJSON_Hold(t *testing.T) {
	srv, client := newTestJudgeServer(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("not json"))
	})
	defer srv.Close()

	out, err := client.Evaluate(EvaluateInput{CageType: "discovery", VulnClass: "sqli", AssessmentID: "assess-1", Method: "GET", URL: "/api", Body: nil})
	assert.Error(t, err)
	assert.Equal(t, PayloadHold, out.Decision)
}

func TestJudge_NoToolCall_Hold(t *testing.T) {
	srv, client := newTestJudgeServer(func(w http.ResponseWriter, r *http.Request) {
		// LLM returned a text answer instead of calling the tool — e.g.
		// because the operator's custom webhook stripped the tool def.
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"I think it's safe"}}]}`))
	})
	defer srv.Close()

	out, err := client.Evaluate(EvaluateInput{CageType: "discovery", VulnClass: "sqli", AssessmentID: "assess-1", Method: "GET", URL: "/api"})
	assert.Error(t, err)
	assert.Equal(t, PayloadHold, out.Decision)
}

func TestJudge_WrongFunctionName_Hold(t *testing.T) {
	srv, client := newTestJudgeServer(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintln(w, `{"choices":[{"message":{"tool_calls":[{"function":{"name":"something_else","arguments":"{}"}}]}}]}`)
	})
	defer srv.Close()

	out, err := client.Evaluate(EvaluateInput{CageType: "discovery", VulnClass: "sqli", AssessmentID: "assess-1", Method: "GET", URL: "/api"})
	assert.Error(t, err)
	assert.Equal(t, PayloadHold, out.Decision)
}

func TestJudge_InvalidConfidence_Hold(t *testing.T) {
	srv, client := newTestJudgeServer(func(w http.ResponseWriter, r *http.Request) {
		respondToolCall(w, true, 1.5, "impossible", nil)
	})
	defer srv.Close()

	out, err := client.Evaluate(EvaluateInput{CageType: "discovery", VulnClass: "sqli", AssessmentID: "assess-1", Method: "GET", URL: "/api", Body: nil})
	assert.Error(t, err)
	assert.Equal(t, PayloadHold, out.Decision)
}

func TestJudge_AuthHeaderSent(t *testing.T) {
	var gotAuth string
	srv, client := newTestJudgeServer(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("x-api-key")
		respondToolCall(w, true, 0.9, "ok", nil)
	})
	defer srv.Close()

	_, err := client.Evaluate(EvaluateInput{CageType: "discovery", VulnClass: "sqli", AssessmentID: "assess-1", Method: "GET", URL: "/api", Body: nil})
	require.NoError(t, err)
	assert.Equal(t, "test-key", gotAuth)
}

func TestJudge_RequestShape_OpenAICompat(t *testing.T) {
	var gotReq struct {
		Messages []struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		} `json:"messages"`
		Tools      []any  `json:"tools"`
		ToolChoice string `json:"tool_choice"`
	}
	srv, client := newTestJudgeServer(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&gotReq)
		respondToolCall(w, true, 0.9, "ok", nil)
	})
	defer srv.Close()

	_, err := client.Evaluate(EvaluateInput{
		CageType: "exploitation", VulnClass: "rce", AssessmentID: "assess-42",
		Method: "POST", URL: "/exec", Body: []byte("whoami"),
		Objective: "test /exec for RCE", AgentReason: "command injection probe",
	})
	require.NoError(t, err)
	require.Len(t, gotReq.Messages, 2)
	assert.Equal(t, "system", gotReq.Messages[0].Role)
	assert.Equal(t, "user", gotReq.Messages[1].Role)
	assert.Contains(t, gotReq.Messages[1].Content, "vuln_class: rce")
	assert.Contains(t, gotReq.Messages[1].Content, "url: /exec")
	assert.Contains(t, gotReq.Messages[1].Content, "objective: test /exec for RCE")
	assert.Contains(t, gotReq.Messages[1].Content, "agent_reason: command injection probe")
	assert.Contains(t, gotReq.Messages[1].Content, "whoami")
	assert.Equal(t, "required", gotReq.ToolChoice)
	require.Len(t, gotReq.Tools, 1)
}

func TestJudge_ServerError_Hold(t *testing.T) {
	srv, client := newTestJudgeServer(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	defer srv.Close()

	out, err := client.Evaluate(EvaluateInput{CageType: "discovery", VulnClass: "sqli", AssessmentID: "assess-1", Method: "GET", URL: "/api", Body: nil})
	assert.Error(t, err)
	assert.Equal(t, PayloadHold, out.Decision)
}
