package main

import (
	"testing"
)

func TestRunCmd_RequiresBundleArg(t *testing.T) {
	cmd := newRunCmd()
	cmd.SetArgs([]string{})
	err := cmd.Execute()
	if err == nil {
		t.Fatalf("expected missing-arg error")
	}
}

func TestRunCmd_RejectsTooManyArgs(t *testing.T) {
	cmd := newRunCmd()
	cmd.SetArgs([]string{"a.agent", "b", "c"})
	err := cmd.Execute()
	if err == nil {
		t.Fatalf("expected too-many-args error")
	}
}
