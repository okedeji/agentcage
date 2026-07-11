package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/okedeji/mcpvessel/internal/env"
	"github.com/okedeji/mcpvessel/internal/signing"
)

func TestKeysCmd_GeneratesAndShows(t *testing.T) {
	t.Setenv(env.Home, t.TempDir())

	cmd := newKeysCmd()
	var out, errOut bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errOut)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("keys: %v", err)
	}
	if !strings.Contains(out.String(), "Fingerprint:") || !strings.Contains(out.String(), "Public key:") {
		t.Errorf("output missing key fields: %q", out.String())
	}
	if !strings.Contains(errOut.String(), "Generated") {
		t.Errorf("first run should note generation on stderr: %q", errOut.String())
	}

	// Second run reloads the same key silently.
	cmd2 := newKeysCmd()
	var out2, errOut2 bytes.Buffer
	cmd2.SetOut(&out2)
	cmd2.SetErr(&errOut2)
	if err := cmd2.Execute(); err != nil {
		t.Fatalf("second keys: %v", err)
	}
	if errOut2.Len() != 0 {
		t.Errorf("second run should not regenerate: %q", errOut2.String())
	}
	if out.String() != out2.String() {
		t.Error("key changed between runs")
	}
}

func TestTrustCmd_LsEmptyAndRm(t *testing.T) {
	t.Setenv(env.Home, t.TempDir())

	ls := newTrustCmd()
	var out bytes.Buffer
	ls.SetOut(&out)
	ls.SetArgs([]string{"ls"})
	if err := ls.Execute(); err != nil {
		t.Fatalf("trust ls: %v", err)
	}
	if !strings.Contains(out.String(), "No pinned keys") {
		t.Errorf("empty store should say so: %q", out.String())
	}

	// Pin a key through the policy path, then list and remove it.
	key, _, _ := signing.EnsureKey()
	sig, _ := signing.Sign(key, "sha256:abc", "ghcr.io/okedeji/researcher")
	if err := signing.VerifyPull(sig, "sha256:abc", "ghcr.io", "okedeji/researcher", nil); err != nil {
		t.Fatalf("pin: %v", err)
	}

	ls2 := newTrustCmd()
	var out2 bytes.Buffer
	ls2.SetOut(&out2)
	ls2.SetArgs([]string{"ls"})
	if err := ls2.Execute(); err != nil {
		t.Fatalf("trust ls: %v", err)
	}
	if !strings.Contains(out2.String(), "ghcr.io/okedeji") {
		t.Errorf("pinned scope missing from ls: %q", out2.String())
	}

	rm := newTrustCmd()
	var out3 bytes.Buffer
	rm.SetOut(&out3)
	rm.SetArgs([]string{"rm", "ghcr.io/okedeji"})
	if err := rm.Execute(); err != nil {
		t.Fatalf("trust rm: %v", err)
	}
	if !strings.Contains(out3.String(), "Removed pin") {
		t.Errorf("rm output: %q", out3.String())
	}

	rm2 := newTrustCmd()
	rm2.SilenceErrors = true
	rm2.SilenceUsage = true
	rm2.SetOut(&bytes.Buffer{})
	rm2.SetErr(&bytes.Buffer{})
	rm2.SetArgs([]string{"rm", "ghcr.io/okedeji"})
	if err := rm2.Execute(); err == nil {
		t.Fatal("removing an absent pin must error")
	}
}
