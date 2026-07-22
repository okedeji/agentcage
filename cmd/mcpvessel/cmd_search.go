package main

import (
	"context"
	"encoding/json"
	"io"
	"strings"

	"github.com/spf13/cobra"

	"github.com/okedeji/mcpvessel/internal/cliout"
	"github.com/okedeji/mcpvessel/internal/mcpregistry"
	"github.com/okedeji/mcpvessel/internal/store"
)

func newSearchCmd() *cobra.Command {
	var jsonOut, local bool
	var limit int
	cmd := &cobra.Command{
		Use:   "search QUERY",
		Short: "Search the MCP Registry for agents",
		Long: `Search the public MCP Registry by name and print matching agents.

Each row is one agent: its reverse-DNS name, latest version, eval signal (when
the author stamped one), and description. Pull a hit with 'mcpvessel pull <name>'
or wrap and build it with 'mcpvessel import <name>'. With --local, search the
bundles already in your local store instead of the registry.`,
		Example: `  mcpvessel search "web search"
  mcpvessel search filesystem --limit 5
  mcpvessel search fs --local`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if local {
				return searchLocal(cmd.OutOrStdout(), args[0], jsonOut)
			}
			return searchRegistry(cmd.Context(), cmd.OutOrStdout(), args[0], limit, jsonOut)
		},
	}
	cmd.Flags().BoolVar(&jsonOut, "json", false, "emit machine-readable JSON")
	cmd.Flags().BoolVar(&local, "local", false, "search the local store instead of the MCP Registry")
	cmd.Flags().IntVar(&limit, "limit", 20, "maximum results to return")
	return cmd
}

func searchRegistry(ctx context.Context, w io.Writer, query string, limit int, jsonOut bool) error {
	servers, err := mcpregistry.New().Search(ctx, query, limit)
	if err != nil {
		return err
	}
	if jsonOut {
		return writeJSON(w, servers)
	}
	printSearchResults(w, servers)
	return nil
}

func searchLocal(w io.Writer, query string, jsonOut bool) error {
	entries, err := store.List()
	if err != nil {
		return err
	}
	var hits []store.Entry
	for _, e := range entries {
		if strings.Contains(e.Ref, query) {
			hits = append(hits, e)
		}
	}
	if jsonOut {
		return writeJSON(w, hits)
	}
	printStoreEntries(w, hits)
	return nil
}

// printSearchResults clips descriptions so one long entry cannot wreck the
// column alignment.
func printSearchResults(w io.Writer, servers []mcpregistry.Server) {
	if len(servers) == 0 {
		cliout.Empty(w, "No matches in the MCP Registry.")
		return
	}
	rows := make([][]string, 0, len(servers))
	for _, s := range servers {
		rows = append(rows, []string{s.Name, s.Version, s.EvalSummary(), clip(s.Description, 60)})
	}
	cliout.Table(w, []string{"NAME", "VERSION", "EVALS", "DESCRIPTION"}, rows)
}

func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func clip(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-1] + "…"
}
