package daemon

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/okedeji/mcpvessel/internal/history"
)

func TestWriteMetrics(t *testing.T) {
	d := New()
	store, err := history.Open(filepath.Join(t.TempDir(), "h.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	d.hist = store

	for _, r := range []history.Record{
		{RunID: "r1", Status: history.StatusSucceeded, CostMicroUSD: 12_000, TotalTokens: 1_500},
		{RunID: "r2", Status: history.StatusSucceeded, CostMicroUSD: 8_000, TotalTokens: 500},
		{RunID: "r3", Status: history.StatusFailed},
	} {
		if err := store.Put(r); err != nil {
			t.Fatal(err)
		}
	}

	var b strings.Builder
	d.writeMetrics(&b)
	out := b.String()

	for _, want := range []string{
		`mcpvessel_runs_total{status="succeeded"} 2`,
		`mcpvessel_runs_total{status="failed"} 1`,
		"mcpvessel_runs_live 0",
		"# TYPE mcpvessel_cages_live gauge",
		"mcpvessel_serve_clients 0",
		"mcpvessel_cost_usd_total 0.020000",
		"mcpvessel_tokens_total 2000",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("metrics output missing %q in:\n%s", want, out)
		}
	}
}
