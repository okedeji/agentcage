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
	"time"

	agentcage "github.com/okedeji/agentcage"
	"github.com/okedeji/agentcage/internal/config"
	"github.com/okedeji/agentcage/internal/enforcement"
	"github.com/okedeji/agentcage/internal/gateway"
	proxylog "github.com/okedeji/agentcage/internal/log"
)

func main() {
	listenAddr := flag.String("listen", ":8080", "proxy listen address")
	targetAddr := flag.String("target", "", "upstream target address")
	vulnClass := flag.String("vuln-class", "", "vulnerability class for blocklist selection")
	classificationEndpoint := flag.String("classification-endpoint", "", "external classification service URL")
	classificationTimeout := flag.Duration("classification-timeout", 5*time.Second, "timeout for classification requests")
	confidenceThreshold := flag.Float64("confidence-threshold", 0.8, "minimum confidence to allow a payload")
	batchWindow := flag.Duration("batch-window", 100*time.Millisecond, "time window for batching classification requests")
	maxBatch := flag.Int("max-batch", 10, "maximum batch size before immediate flush")
	onUncertain := flag.String("on-uncertain", "block", "action when confidence is below threshold: block or hold")
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

	cfg, err := config.Default(agentcage.DefaultConfigYAML)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: loading default config: %v\n", err)
		os.Exit(1)
	}

	entries := cfg.BlocklistPatterns[*vulnClass]
	patterns := make(map[string]string, len(entries))
	for _, e := range entries {
		patterns[e.Pattern] = e.Message
	}

	var classifyCfg *enforcement.ProxyClassifyConfig
	if *classificationEndpoint != "" {
		uncertainDecision := enforcement.PayloadBlock
		if *onUncertain == "hold" {
			uncertainDecision = enforcement.PayloadHold
		}

		client := enforcement.NewClassificationClient(*classificationEndpoint, *classificationTimeout)
		batcher := enforcement.NewPayloadBatcher(client, *batchWindow, *maxBatch)

		classifyCfg = &enforcement.ProxyClassifyConfig{
			Batcher:     batcher,
			Threshold:   *confidenceThreshold,
			OnUncertain: uncertainDecision,
		}
	}

	engine, err := enforcement.NewProxyEngine(*vulnClass, patterns, classifyCfg)
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

	useClassification := classifyCfg != nil

	var llmHost string
	if *llmEndpoint != "" {
		if parsed, err := url.Parse(*llmEndpoint); err == nil {
			llmHost = parsed.Host
		}
	}

	llmProxy := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			if parsed, err := url.Parse(*llmEndpoint); err == nil {
				req.URL.Scheme = parsed.Scheme
				req.URL.Host = parsed.Host
				req.Host = parsed.Host
			}
		},
		ModifyResponse: func(resp *http.Response) error {
			const maxRespSize = 10 << 20 // 10MB
			respBody, err := io.ReadAll(io.LimitReader(resp.Body, int64(maxRespSize)+1))
			if err != nil {
				return err
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
			if err := json.Unmarshal(respBody, &llmResp); err == nil && llmResp.Usage.TotalTokens > 0 {
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
			bodyBytes, err = io.ReadAll(io.LimitReader(r.Body, maxBodySize+1))
			if err != nil {
				http.Error(w, "failed to read request body", http.StatusBadGateway)
				return
			}
			r.Body.Close()
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

		// Target requests: inspect payload
		if useClassification {
			decision, reason, classErr := engine.InspectWithClassification(r.Context(), r.Method, r.URL.String(), bodyBytes)
			if classErr != nil {
				logger.Error(classErr, "classification error", "method", r.Method, "url", r.URL.String())
			}

			switch decision {
			case enforcement.PayloadBlock:
				logger.Info("payload blocked", "method", r.Method, "url", r.URL.String(), "reason", reason)
				http.Error(w, fmt.Sprintf("blocked by payload proxy: %s", reason), http.StatusForbidden)
				return
			case enforcement.PayloadHold:
				logger.Info("payload held", "method", r.Method, "url", r.URL.String(), "reason", reason)
				http.Error(w, fmt.Sprintf("payload held for review: %s", reason), http.StatusServiceUnavailable)
				return
			default:
				logger.V(1).Info("payload allowed", "method", r.Method, "url", r.URL.String())
			}
		} else {
			decision, reason := engine.Inspect(r.Method, r.URL.String(), bodyBytes)
			if decision == enforcement.PayloadBlock {
				logger.Info("payload blocked", "method", r.Method, "url", r.URL.String(), "reason", reason)
				http.Error(w, fmt.Sprintf("blocked by payload proxy: %s", reason), http.StatusForbidden)
				return
			}
			logger.V(1).Info("payload allowed", "method", r.Method, "url", r.URL.String())
		}

		if len(bodyBytes) > 0 {
			r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
			r.ContentLength = int64(len(bodyBytes))
		}
		proxy.ServeHTTP(w, r)
	})

	logger.Info("starting payload proxy", "listen", *listenAddr, "target", *targetAddr, "classification_enabled", useClassification, "llm_metering_enabled", llmHost != "")
	if err := http.ListenAndServe(*listenAddr, handler); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}
