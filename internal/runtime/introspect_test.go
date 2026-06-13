package runtime

import (
	"strings"
	"testing"
)

func TestIntrospectRunID(t *testing.T) {
	got := introspectRunID("agentcage/researcher:latest")
	if !strings.HasSuffix(got, "-introspect") {
		t.Errorf("introspectRunID = %q, want a -introspect suffix", got)
	}
	// The image ref's slashes and colons must be sanitized to a valid
	// container name.
	if strings.ContainsAny(got, "/:") {
		t.Errorf("introspectRunID = %q still contains /:", got)
	}
}
