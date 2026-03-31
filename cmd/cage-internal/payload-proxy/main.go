package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"

	"github.com/okedeji/agentcage/internal/config"
	"github.com/okedeji/agentcage/internal/enforcement"
	"github.com/okedeji/agentcage/internal/gateway"
	proxylog "github.com/okedeji/agentcage/internal/log"
)

func main() {
	listenAddr := flag.String("listen", ":8080", "proxy listen address")
	targetAddr := flag.String("target", "", "upstream target address")
	vulnClass := flag.String("vuln-class", "", "vulnerability class for blocklist selection")
	llmEndpoint := flag.String("llm-endpoint", "", "external LLM endpoint URL — requests to this host are metered, not inspected")
	flag.Parse()

	if *targetAddr == "" {
		fmt.Fprintln(os.Stderr, "error: -target is required")
		os.Exit(1)
	}

	target, err := url.Parse(*targetAddr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: invalid target URL: %v\n", err)
		os.Exit(1)
	}

	cfg := config.Defaults()

	allPatterns := cfg.BlocklistPatterns()
	entries := allPatterns[*vulnClass]
	patterns := make(map[string]string, len(entries))
	for _, e := range entries {
		patterns[e.Pattern] = e.Reason
	}

	engine, err := enforcement.NewProxyEngine(*vulnClass, patterns)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: compiling proxy patterns: %v\n", err)
		os.Exit(1)
	}

	logger, err := proxylog.New()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: creating logger: %v\n", err)
		os.Exit(1)
	}
	logger = logger.WithValues("component", "payload-proxy", "vuln_class", *vulnClass)

	proxy := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = target.Scheme
			req.URL.Host = target.Host
			req.Host = target.Host
		},
	}

	var llmHost string
	if *llmEndpoint != "" {
		if parsed, parseErr := url.Parse(*llmEndpoint); parseErr == nil {
			llmHost = parsed.Host
		}
	}

	llmProxy := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			if parsed, parseErr := url.Parse(*llmEndpoint); parseErr == nil {
				req.URL.Scheme = parsed.Scheme
				req.URL.Host = parsed.Host
				req.Host = parsed.Host
			}
		},
		ModifyResponse: func(resp *http.Response) error {
			const maxRespSize = 10 << 20 // 10MB
			respBody, readErr := io.ReadAll(io.LimitReader(resp.Body, int64(maxRespSize)+1))
			if readErr != nil {
				return readErr
			}
			if len(respBody) > maxRespSize {
				logger.Info("llm response too large", "size", len(respBody))
				resp.StatusCode = http.StatusBadGateway
				resp.Status = "502 Bad Gateway"
				msg := []byte("LLM response exceeds 10MB limit")
				resp.Body = io.NopCloser(bytes.NewReader(msg))
				resp.ContentLength = int64(len(msg))
				return nil
			}
			resp.Body = io.NopCloser(bytes.NewReader(respBody))

			var llmResp gateway.LLMResponse
			if jsonErr := json.Unmarshal(respBody, &llmResp); jsonErr == nil && llmResp.Usage.TotalTokens > 0 {
				logger.Info("llm_usage",
					"model", llmResp.Model,
					"prompt_tokens", llmResp.Usage.PromptTokens,
					"completion_tokens", llmResp.Usage.CompletionTokens,
					"total_tokens", llmResp.Usage.TotalTokens,
				)
			}
			return nil
		},
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		const maxBodySize = 10 << 20 // 10MB
		var bodyBytes []byte
		if r.Body != nil {
			var readErr error
			bodyBytes, readErr = io.ReadAll(io.LimitReader(r.Body, maxBodySize+1))
			if readErr != nil {
				http.Error(w, "failed to read request body", http.StatusBadGateway)
				return
			}
			_ = r.Body.Close()
			if len(bodyBytes) > maxBodySize {
				logger.Info("request body too large", "method", r.Method, "url", r.URL.String(), "size", len(bodyBytes))
				http.Error(w, "request body exceeds 10MB limit", http.StatusRequestEntityTooLarge)
				return
			}
		}

		// LLM requests: forward and meter, skip payload inspection
		if llmHost != "" && strings.Contains(r.URL.Host, llmHost) {
			if len(bodyBytes) > 0 {
				r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
				r.ContentLength = int64(len(bodyBytes))
			}
			logger.V(1).Info("llm request forwarded", "method", r.Method, "url", r.URL.String())
			llmProxy.ServeHTTP(w, r)
			return
		}

		// Target requests: inspect payload against blocklist
		decision, reason := engine.Inspect(r.Method, r.URL.String(), bodyBytes)
		if decision == enforcement.PayloadBlock {
			logger.Info("payload blocked", "method", r.Method, "url", r.URL.String(), "reason", reason)
			http.Error(w, fmt.Sprintf("blocked by payload proxy: %s", reason), http.StatusForbidden)
			return
		}
		logger.V(1).Info("payload allowed", "method", r.Method, "url", r.URL.String())

		if len(bodyBytes) > 0 {
			r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
			r.ContentLength = int64(len(bodyBytes))
		}
		proxy.ServeHTTP(w, r)
	})

	logger.Info("starting payload proxy", "listen", *listenAddr, "target", *targetAddr, "llm_metering_enabled", llmHost != "")
	if srvErr := http.ListenAndServe(*listenAddr, handler); srvErr != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", srvErr)
		os.Exit(1)
	}
}
