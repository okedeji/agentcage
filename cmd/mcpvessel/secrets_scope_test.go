package main

import (
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/okedeji/mcpvessel/internal/runtime"
)

func TestBuildInputPools_ScopedSecrets(t *testing.T) {
	t.Setenv("SHARED_KEY", "shared-value")
	t.Setenv("SENTRY_TOKEN", "sentry-value")

	_, pool, err := buildInputPools(nil, "", []string{"SHARED_KEY", "sentry-tools:SENTRY_TOKEN"}, "")
	if err != nil {
		t.Fatalf("buildInputPools: %v", err)
	}
	want := runtime.ScopedSecrets{
		"":             {"SHARED_KEY": "shared-value"},
		"sentry-tools": {"SENTRY_TOKEN": "sentry-value"},
	}
	if !reflect.DeepEqual(pool, want) {
		t.Errorf("pool = %v, want %v", pool, want)
	}
	// The scoped value resolves by its bare name, and never reaches an agent
	// outside its scope.
	if v := pool.For("brave-tools")["SENTRY_TOKEN"]; v != "" {
		t.Errorf("scoped secret leaked to another agent: %q", v)
	}
	if v := pool.For("sentry-tools")["SENTRY_TOKEN"]; v != "sentry-value" {
		t.Errorf("scoped secret missing in its own scope: %q", v)
	}
}

func TestBuildInputPools_SecretFileScopes(t *testing.T) {
	file := filepath.Join(t.TempDir(), "secrets.env")
	if err := os.WriteFile(file, []byte("# comment\nBROAD=b\nsentry-tools:PINNED=p\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, pool, err := buildInputPools(nil, "", nil, file)
	if err != nil {
		t.Fatalf("buildInputPools: %v", err)
	}
	want := runtime.ScopedSecrets{
		"":             {"BROAD": "b"},
		"sentry-tools": {"PINNED": "p"},
	}
	if !reflect.DeepEqual(pool, want) {
		t.Errorf("pool = %v, want %v", pool, want)
	}
}

func TestBuildInputPools_SecretFileRejectsLoosePerms(t *testing.T) {
	file := filepath.Join(t.TempDir(), "secrets.env")
	if err := os.WriteFile(file, []byte("TOKEN=v\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, _, err := buildInputPools(nil, "", nil, file)
	if err == nil {
		t.Fatal("expected a rejection for a group/other-readable secret file")
	}
	if !strings.Contains(err.Error(), "group/other") {
		t.Errorf("error = %q, want it to name the loose permissions", err.Error())
	}

	// The exact contract: mode 0600 is accepted.
	if err := os.Chmod(file, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := buildInputPools(nil, "", nil, file); err != nil {
		t.Errorf("0600 secret file rejected: %v", err)
	}
}

func TestApplyConfigSecrets_ScopesPerAgentBindings(t *testing.T) {
	home := t.TempDir()
	t.Setenv("VESSEL_HOME", home)
	cfg := `{"secrets":{"defaults":["SHARED"],"agents":{` +
		`"@me/github:0.1":["GH_TOKEN"],` +
		`"@me/notion":["NOTION_TOKEN"]}}}`
	if err := os.WriteFile(filepath.Join(home, "config.json"), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SHARED", "shared-v")
	t.Setenv("GH_TOKEN", "gh-v")
	t.Setenv("NOTION_TOKEN", "notion-v")

	pool := runtime.ScopedSecrets{}
	if err := applyConfigSecrets(pool, "@me/github:0.1", io.Discard); err != nil {
		t.Fatalf("applyConfigSecrets: %v", err)
	}

	// The general default broadcasts; a per-agent binding lands only in that
	// agent's scope (its short name), never the broadcast pool.
	if pool[""]["SHARED"] != "shared-v" {
		t.Errorf("default not broadcast: %v", pool[""])
	}
	if _, leaked := pool[""]["GH_TOKEN"]; leaked {
		t.Error("a per-agent binding leaked into the broadcast pool")
	}
	if pool["github"]["GH_TOKEN"] != "gh-v" {
		t.Errorf("github binding not scoped to its agent: %v", pool["github"])
	}
	// A sub-agent binding is applied too (the old broadcast-only path dropped
	// it), scoped to the sub-agent, not broadcast.
	if pool["notion"]["NOTION_TOKEN"] != "notion-v" {
		t.Errorf("sub-agent binding not applied to its scope: %v", pool["notion"])
	}
	if _, leaked := pool[""]["NOTION_TOKEN"]; leaked {
		t.Error("a sub-agent binding leaked into the broadcast pool")
	}
}

func TestApplyConfigSecrets_DoesNotOverrideExplicitGrant(t *testing.T) {
	home := t.TempDir()
	t.Setenv("VESSEL_HOME", home)
	if err := os.WriteFile(filepath.Join(home, "config.json"),
		[]byte(`{"secrets":{"agents":{"@me/github":["GH_TOKEN"]}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GH_TOKEN", "from-config")

	pool := runtime.ScopedSecrets{"github": {"GH_TOKEN": "from-flag"}}
	if err := applyConfigSecrets(pool, "@me/github", io.Discard); err != nil {
		t.Fatalf("applyConfigSecrets: %v", err)
	}
	if pool["github"]["GH_TOKEN"] != "from-flag" {
		t.Errorf("config binding overrode an explicit --secret: %v", pool["github"])
	}
}

func TestFormatSecretGrants(t *testing.T) {
	cases := []struct {
		name     string
		declared []string
		optional []string
		pool     map[string]string
		want     string
	}{
		{"none declared", nil, nil, nil, "none declared"},
		{"granted", []string{"TOKEN"}, nil, map[string]string{"TOKEN": "v"}, "TOKEN (granted)"},
		{"missing required", []string{"TOKEN"}, nil, nil, "TOKEN (missing; pass --secret TOKEN)"},
		{"missing optional", []string{"TOKEN"}, []string{"TOKEN"}, nil, "TOKEN (optional, not granted)"},
		{"sorted mix", []string{"B_KEY", "A_KEY"}, nil, map[string]string{"A_KEY": "v"}, "A_KEY (granted), B_KEY (missing; pass --secret B_KEY)"},
	}
	for _, tc := range cases {
		if got := formatSecretGrants(tc.declared, tc.optional, tc.pool); got != tc.want {
			t.Errorf("%s: formatSecretGrants = %q, want %q", tc.name, got, tc.want)
		}
	}
	// Values never appear, whatever the pool holds.
	out := formatSecretGrants([]string{"TOKEN"}, nil, map[string]string{"TOKEN": "sk-supersecret"})
	if strings.Contains(out, "sk-supersecret") {
		t.Errorf("grant line leaks a value: %q", out)
	}
}
