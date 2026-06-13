package runtime

import (
	"strings"
	"testing"
)

func TestIntrospectRunID(t *testing.T) {
	got := introspectRunID("agentcage/researcher:latest")
	// Carries the -introspect tag plus a PID for uniqueness across
	// concurrent builds.
	if !strings.Contains(got, "-introspect-") {
		t.Errorf("introspectRunID = %q, want a -introspect- segment", got)
	}
	// The image ref's slashes and colons must be sanitized to a valid
	// container name.
	if strings.ContainsAny(got, "/:") {
		t.Errorf("introspectRunID = %q still contains /:", got)
	}
}
