package main

import (
	"bytes"
	"strings"
	"testing"
)

// TestPullCmd_RequiresVersion locks the one piece of pull that runs
// before any network call: a bare @org/name with no tag or digest is
// rejected, so the command never reaches the registry without knowing
// what to fetch.
func TestPullCmd_RequiresVersion(t *testing.T) {
	cmd := newPullCmd()
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"@okedeji/researcher"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected a rejection: pull without a tag or digest must error")
	}
	if !strings.Contains(err.Error(), "version tag or digest") {
		t.Errorf("error %q should explain a version is required", err.Error())
	}
}
