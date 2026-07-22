package main

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/okedeji/mcpvessel/internal/daemon"
	"github.com/okedeji/mcpvessel/internal/telemetry"
)

func newTraceCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "trace RUN",
		Short: "Show a run's trace",
		Long: `Render a finished run's trace as a tree: the run, each agent that reasoned, and
every LLM call it made with its model, tokens, cost, and duration.

The run id is the one 'mcpvessel ps' lists. A run that made no LLM call has no
trace.`,
		Example: `  mcpvessel trace researcher-7a1c4f2e9d3b`,
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			socket, err := daemon.SocketPath()
			if err != nil {
				return err
			}
			tr, err := daemon.Dial(socket).Trace(cmd.Context(), args[0])
			if err != nil {
				var unreachable *daemon.Unreachable
				if errors.As(err, &unreachable) {
					return fmt.Errorf("%w (the daemon is not running; start it with 'mcpvessel init')", err)
				}
				return err
			}
			printTrace(cmd.OutOrStdout(), tr)
			return nil
		},
	}
	return cmd
}

func printTrace(w io.Writer, tr *telemetry.Trace) {
	if tr.Root == nil {
		return
	}
	printSpan(w, tr.Root, 0)
}

func printSpan(w io.Writer, s *telemetry.Span, depth int) {
	line := strings.Repeat("  ", depth) + s.Name
	if d := s.Duration(); d > 0 {
		line += "  " + d.Round(time.Millisecond).String()
	}
	if attrs := spanAttrs(s); attrs != "" {
		line += "  " + attrs
	}
	_, _ = fmt.Fprintln(w, line)
	for _, c := range s.Children {
		printSpan(w, c, depth+1)
	}
}

// spanAttrs summarizes an LLM call span (model, tokens, cost); empty for
// structural spans.
func spanAttrs(s *telemetry.Span) string {
	model, _ := s.Attributes["model"].(string)
	if model == "" {
		return ""
	}
	parts := []string{model}
	if in, ok := numAttr(s.Attributes["prompt_tokens"]); ok {
		out, _ := numAttr(s.Attributes["completion_tokens"])
		parts = append(parts, fmt.Sprintf("%d->%d tok", in, out))
	}
	if micro, ok := numAttr(s.Attributes["cost_micro_usd"]); ok && micro > 0 {
		parts = append(parts, "$"+formatUSDMicros(micro))
	}
	return strings.Join(parts, "  ")
}

// numAttr reads an integer attribute that survived a JSON round-trip as float64.
func numAttr(v any) (int64, bool) {
	switch n := v.(type) {
	case float64:
		return int64(n), true
	case int64:
		return n, true
	}
	return 0, false
}
