package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"

	agentcage "github.com/okedeji/agentcage"
	"github.com/okedeji/agentcage/internal/config"
	"github.com/okedeji/agentcage/internal/enforcement"
	proxylog "github.com/okedeji/agentcage/internal/log"
)

func main() {
	listenAddr := flag.String("listen", ":8080", "proxy listen address")
	targetAddr := flag.String("target", "", "upstream target address")
	vulnClass := flag.String("vuln-class", "", "vulnerability class for blocklist selection")
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

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var bodyBytes []byte
		if r.Body != nil {
			bodyBytes, err = io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, "failed to read request body", http.StatusBadGateway)
				return
			}
			r.Body.Close()
		}

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

	logger.Info("starting payload proxy", "listen", *listenAddr, "target", *targetAddr)
	if err := http.ListenAndServe(*listenAddr, handler); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}
