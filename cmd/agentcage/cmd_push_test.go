package main

import (
	"bytes"
	"strings"
	"testing"
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
