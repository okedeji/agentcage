package main

import (
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
