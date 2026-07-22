package main

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/okedeji/mcpvessel/internal/daemon"
)

func TestSince(t *testing.T) {
	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	nowFunc = func() time.Time { return base }
	t.Cleanup(func() { nowFunc = time.Now })

	cases := []struct {
		name    string
		started time.Time
		want    string
	}{
		{"zero", time.Time{}, "-"},
		{"seconds", base.Add(-30 * time.Second), "30s"},
		{"minutes", base.Add(-5 * time.Minute), "5m"},
		{"hours", base.Add(-2 * time.Hour), "2h"},
	}
	for _, tc := range cases {
		if got := since(tc.started); got != tc.want {
			t.Errorf("%s: since = %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestPrintRuns_EmptyStateAndRows(t *testing.T) {
	var empty bytes.Buffer
	printRuns(&empty, nil, false)
	if !strings.Contains(empty.String(), "No runs yet") {
		t.Errorf("empty ps should print the empty state, not a bare header:\n%s", empty.String())
	}

	var buf bytes.Buffer
	printRuns(&buf, []daemon.RunInfo{
		{ID: "researcher-abc", Ref: "@me/researcher:0.1", Status: "running", StartedAt: time.Now()},
	}, false)
	out := buf.String()
	for _, want := range []string{"RUN ID", "researcher-abc", "@me/researcher:0.1", "running"} {
		if !strings.Contains(out, want) {
			t.Errorf("ps output missing %q:\n%s", want, out)
		}
	}
}

func TestPrintRuns_LiveFirstAndElision(t *testing.T) {
	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	nowFunc = func() time.Time { return base }
	t.Cleanup(func() { nowFunc = time.Now })

	runs := []daemon.RunInfo{}
	// Twelve finished runs, oldest first, then one live run started before
	// them all: live must still sort first, and only the ten newest finished
	// survive the default view.
	for i := 0; i < 12; i++ {
		runs = append(runs, daemon.RunInfo{
			ID: "done-" + string(rune('a'+i)), Ref: "@me/x:0.1", Status: "succeeded",
			StartedAt: base.Add(time.Duration(-60+i) * time.Minute), EndedAt: base,
		})
	}
	runs = append(runs, daemon.RunInfo{ID: "live-1", Ref: "@me/x:0.1", Status: "serving", StartedAt: base.Add(-3 * time.Hour)})

	var buf bytes.Buffer
	printRuns(&buf, runs, false)
	out := buf.String()
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if !strings.HasPrefix(lines[1], "live-1") {
		t.Errorf("live run must sort first:\n%s", out)
	}
	if strings.Contains(out, "done-a ") || !strings.Contains(out, "older; 'mcpvessel ps -a' shows all") {
		t.Errorf("default view must elide old finished runs behind the -a trailer:\n%s", out)
	}

	buf.Reset()
	printRuns(&buf, runs, true)
	if !strings.Contains(buf.String(), "done-a") {
		t.Errorf("-a must show the full history:\n%s", buf.String())
	}
}
