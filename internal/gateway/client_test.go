package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func validLLMResponse() LLMResponse {
	return LLMResponse{
		ID:    "chatcmpl-abc123",
		Model: "gpt-4",
		Choices: []LLMChoice{
			{Index: 0, Message: LLMMessage{Role: "assistant", Content: "Hello"}},
		},
		Usage: LLMUsage{
			PromptTokens:     10,
			CompletionTokens: 5,
			TotalTokens:      15,
		},
	}
}

func newTestClient(serverURL string) (*Client, *TokenMeter) {
	meter := NewTokenMeter()
	budget := NewBudgetEnforcer(meter)
	client := NewClient(serverURL, "", 5*time.Second, meter, budget, nil)
	return client, meter
}

func TestChatCompletion_Success(t *testing.T) {
	resp := validLLMResponse()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	client, meter := newTestClient(srv.URL)

	req := LLMRequest{
		Model:    "gpt-4",
		Messages: []LLMMessage{{Role: "user", Content: "hi"}},
	}

	got, err := client.ChatCompletion(context.Background(), "cage-1", "assess-1", 1000, req)
	require.NoError(t, err)
	assert.Equal(t, "chatcmpl-abc123", got.ID)
	assert.Equal(t, int64(15), got.Usage.TotalTokens)

	usage := meter.GetUsage("cage-1")
	assert.Equal(t, int64(10), usage.InputTokens)
	assert.Equal(t, int64(5), usage.OutputTokens)
}

func TestChatCompletion_BudgetExhausted(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))
	defer srv.Close()

	client, meter := newTestClient(srv.URL)
	meter.Record("cage-1", "assess-1", "gpt-4", 500, 500)

	req := LLMRequest{
		Model:    "gpt-4",
		Messages: []LLMMessage{{Role: "user", Content: "hi"}},
	}

	_, err := client.ChatCompletion(context.Background(), "cage-1", "assess-1", 1000, req)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrBudgetExhausted))
	assert.False(t, called)
}

func TestChatCompletion_MissingUsageData(t *testing.T) {
	resp := LLMResponse{
		ID:    "chatcmpl-abc123",
		Model: "gpt-4",
		Choices: []LLMChoice{
			{Index: 0, Message: LLMMessage{Role: "assistant", Content: "Hello"}},
		},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	client, _ := newTestClient(srv.URL)

	req := LLMRequest{
		Model:    "gpt-4",
		Messages: []LLMMessage{{Role: "user", Content: "hi"}},
	}

	_, err := client.ChatCompletion(context.Background(), "cage-1", "assess-1", 1000, req)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNoUsageData))
}

func TestChatCompletion_Timeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(500 * time.Millisecond)
	}))
	defer srv.Close()

	meter := NewTokenMeter()
	budget := NewBudgetEnforcer(meter)
	client := NewClient(srv.URL, "", 50*time.Millisecond, meter, budget, nil)

	req := LLMRequest{
		Model:    "gpt-4",
		Messages: []LLMMessage{{Role: "user", Content: "hi"}},
	}

	_, err := client.ChatCompletion(context.Background(), "cage-1", "assess-1", 1000, req)
	require.Error(t, err)
	assert.True(t, errors.Is(err, context.DeadlineExceeded))
}

func TestChatCompletion_InvalidJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("not json at all"))
	}))
	defer srv.Close()

	client, _ := newTestClient(srv.URL)

	req := LLMRequest{
		Model:    "gpt-4",
		Messages: []LLMMessage{{Role: "user", Content: "hi"}},
	}

	_, err := client.ChatCompletion(context.Background(), "cage-1", "assess-1", 1000, req)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unmarshaling LLM response")
}

func TestChatCompletion_RequestBodySentCorrectly(t *testing.T) {
	var received LLMRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &received)

		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

		resp := validLLMResponse()
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	client, _ := newTestClient(srv.URL)

	req := LLMRequest{
		Model: "gpt-4",
		Messages: []LLMMessage{
			{Role: "system", Content: "You are helpful"},
			{Role: "user", Content: "hello"},
		},
	}

	_, err := client.ChatCompletion(context.Background(), "cage-1", "assess-1", 1000, req)
	require.NoError(t, err)

	assert.Equal(t, "gpt-4", received.Model)
	require.Len(t, received.Messages, 2)
	assert.Equal(t, "system", received.Messages[0].Role)
	assert.Equal(t, "You are helpful", received.Messages[0].Content)
	assert.Equal(t, "user", received.Messages[1].Role)
	assert.Equal(t, "hello", received.Messages[1].Content)
}
