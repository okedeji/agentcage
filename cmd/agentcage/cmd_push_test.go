package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/okedeji/agentcage/internal/reference"
)

// TestPushCmd_RequiresTag locks push's pre-network rejection: a bare
// @org/name with no tag cannot be published, since the registry needs a
// tag to publish under.
func TestPushCmd_RequiresTag(t *testing.T) {
	cmd := newPushCmd()
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"@okedeji/researcher"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected a rejection: push without a tag must error")
	}
	if !strings.Contains(err.Error(), "version tag is required") {
		t.Errorf("error %q should explain a tag is required", err.Error())
	}
}

func TestDefaultBundleForRef(t *testing.T) {
	cases := []struct {
		repo string
		want string
	}{
		{"okedeji/researcher", "researcher.agent"},
		{"team/sub/web-search", "web-search.agent"},
	}
	for _, tc := range cases {
		ref := reference.Reference{Registry: "ghcr.io", Repository: tc.repo, Tag: "0.1"}
		if got := defaultBundleForRef(ref); got != tc.want {
			t.Errorf("defaultBundleForRef(%q) = %q, want %q", tc.repo, got, tc.want)
		}
	}
}
