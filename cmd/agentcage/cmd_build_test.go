package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/okedeji/agentcage/internal/progress"
	"github.com/okedeji/agentcage/internal/reference"
	"github.com/okedeji/agentcage/internal/store"
)

func TestHumanSize(t *testing.T) {
	cases := []struct {
		in   int64
		want string
	}{
		{0, "0 B"},
		{512, "512 B"},
		{1023, "1023 B"},
		{1024, "1.0 KB"},
		{1500, "1.5 KB"},
		{1<<20 - 1, "1024.0 KB"},
		{1 << 20, "1.0 MB"},
		{12_400_000, "11.8 MB"},
		{1 << 30, "1.0 GB"},
	}
	for _, tc := range cases {
		got := humanSize(tc.in)
		if got != tc.want {
			t.Errorf("humanSize(%d) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestRunBuild_HappyPath(t *testing.T) {
	srcDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(srcDir, "Agentfile"), []byte(
		"FROM python:3.12-slim\nENTRYPOINT python3 agent.py\n",
	), 0o644); err != nil {
		t.Fatalf("WriteFile Agentfile: %v", err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "agent.py"), []byte("print('hi')\n"), 0o644); err != nil {
		t.Fatalf("WriteFile agent.py: %v", err)
	}

	out := filepath.Join(t.TempDir(), "researcher.agent")
	var buf, errBuf bytes.Buffer
	// --no-introspect: the packaging path under test does not boot the
	// agent, so it needs no runtime.
	if err := runBuild(context.Background(), &buf, &errBuf, buildConfig{srcDir: srcDir, outPath: out, mode: progress.ModePlain, noIntrospect: true}); err != nil {
		t.Fatalf("runBuild: %v", err)
	}

	if _, err := os.Stat(out); err != nil {
		t.Errorf("bundle not created at %s: %v", out, err)
	}
	stdout := buf.String()
	for _, want := range []string{
		"Step 1/3 : Parsing Agentfile",
		"Step 2/3 : Hashing source tree",
		"Step 3/3 : Sealing bundle",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("missing %q in output:\n%s", want, stdout)
		}
	}
}

// TestBuildToStore_TagIndexed builds into a store rooted at a temp
// AGENTCAGE_HOME and asserts the bundle lands content-addressed, the -t ref
// resolves back to it, and the result line names the ref. --no-introspect
// keeps it runtime-free.
func TestBuildToStore_TagIndexed(t *testing.T) {
	home := t.TempDir()
	t.Setenv("AGENTCAGE_HOME", home)
	t.Setenv("AGENTCAGE_REGISTRY", "")

	srcDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(srcDir, "Agentfile"), []byte(
		"FROM python:3.12-slim\nENTRYPOINT python3 agent.py\n",
	), 0o644); err != nil {
		t.Fatalf("WriteFile Agentfile: %v", err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "agent.py"), []byte("print('hi')\n"), 0o644); err != nil {
		t.Fatalf("WriteFile agent.py: %v", err)
	}

	var buf, errBuf bytes.Buffer
	if err := buildToStore(context.Background(), &buf, &errBuf, buildConfig{
		srcDir: srcDir, mode: progress.ModePlain, tag: "@okedeji/researcher:0.1", noIntrospect: true,
	}); err != nil {
		t.Fatalf("buildToStore: %v", err)
	}

	if !strings.Contains(buf.String(), "okedeji/researcher:0.1") {
		t.Errorf("result line should name the ref:\n%s", buf.String())
	}

	st, err := store.New()
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	ref, err := reference.Parse("@okedeji/researcher:0.1")
	if err != nil {
		t.Fatalf("reference.Parse: %v", err)
	}
	path, ok, err := st.Get(ref)
	if err != nil {
		t.Fatalf("store.Get: %v", err)
	}
	if !ok {
		t.Fatal("built ref does not resolve in the store")
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("resolved store path is not a file: %v", err)
	}
}

func TestRunBuild_PropagatesBundleError(t *testing.T) {
	// Source dir has no Agentfile, so bundle.Build returns an error.
	srcDir := t.TempDir()
	out := filepath.Join(t.TempDir(), "x.agent")

	var buf, errBuf bytes.Buffer
	err := runBuild(context.Background(), &buf, &errBuf, buildConfig{srcDir: srcDir, outPath: out, mode: progress.ModePlain, noIntrospect: true})
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "Agentfile not found") {
		t.Errorf("error = %q, want 'Agentfile not found'", err.Error())
	}
}
