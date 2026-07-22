package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"

	"github.com/spf13/cobra"

	"github.com/okedeji/mcpvessel/internal/env"
	"github.com/okedeji/mcpvessel/internal/llmgateway"
)

// syncWriter serializes whole-line writes to the underlying stream. The gateway
// emits spend/call/replay lines from many concurrent metered calls, and a
// replay line's base64 payload far exceeds PIPE_BUF, so without this their
// writes would interleave and corrupt the JSON lines the daemon parses.
type syncWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (s *syncWriter) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.w.Write(p)
}

// newLLMGatewayCmd runs the in-run LLM gateway. Hidden: the runtime starts it
// inside the gateway container; its endpoints, per-agent models, and budget
// arrive as injected environment.
func newLLMGatewayCmd() *cobra.Command {
	return &cobra.Command{
		Use:    "llm-gateway",
		Short:  "Run the in-run LLM gateway (internal)",
		Hidden: true,
		Args:   cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			raw := os.Getenv(env.LLMConfig)
			if raw == "" {
				return fmt.Errorf("%s is required", env.LLMConfig)
			}
			var cfg llmgateway.Config
			if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
				return fmt.Errorf("parsing %s: %w", env.LLMConfig, err)
			}
			addr := os.Getenv(env.LLMAddr)
			if addr == "" {
				addr = ":" + env.DefaultLLMGatewayPort
			}
			out := &syncWriter{w: os.Stdout}
			gw := llmgateway.New(cfg, llmgateway.Hooks{
				Spend:   func(r llmgateway.SpendReport) { llmgateway.WriteSpendLine(out, r) },
				Call:    func(e llmgateway.CallEvent) { llmgateway.WriteCallLine(out, e) },
				Payload: func(r llmgateway.CallRecord) { llmgateway.WriteReplayLine(out, r) },
			})
			// An initial zero snapshot, so a spend read early in the run reports
			// the configured budget rather than nothing.
			llmgateway.WriteSpendLine(out, gw.Snapshot())

			// Loopback only: agents on the run network cannot reach the
			// control surface; the daemon drives it via nerdctl exec, inside
			// this container's namespace.
			control := &http.Server{Addr: "127.0.0.1:" + env.DefaultLLMControlPort, Handler: gw.Control()}
			go func() {
				if err := control.ListenAndServe(); err != nil && err != http.ErrServerClosed {
					fmt.Fprintf(os.Stderr, "llm gateway control listener: %v\n", err)
				}
			}()

			srv := &http.Server{Addr: addr, Handler: gw.Handler()}
			return srv.ListenAndServe()
		},
	}
}
