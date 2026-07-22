package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestDaemonStop_NoDaemonRunning(t *testing.T) {
	t.Setenv("VESSEL_HOME", t.TempDir())

	cmd := newDaemonStopCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs(nil)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("daemon stop: %v", err)
	}
	if !strings.Contains(out.String(), "No daemon is running") {
		t.Errorf("output = %q, want the no-daemon message", out.String())
	}
}
