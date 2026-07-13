package main

import (
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func testCmdWithStdin(stdin string) *cobra.Command {
	c := &cobra.Command{}
	c.SetIn(strings.NewReader(stdin))
	return c
}

func TestMCPRegistryGitHubToken_Stdin(t *testing.T) {
	tok, err := mcpRegistryGitHubToken(testCmdWithStdin("ghp_fromstdin\n"), "", true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tok != "ghp_fromstdin" {
		t.Errorf("token = %q, want ghp_fromstdin (trailing newline trimmed)", tok)
	}
}

func TestMCPRegistryGitHubToken_PasswordFlag(t *testing.T) {
	tok, err := mcpRegistryGitHubToken(testCmdWithStdin(""), "ghp_fromflag", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tok != "ghp_fromflag" {
		t.Errorf("token = %q, want ghp_fromflag", tok)
	}
}

func TestMCPRegistryGitHubToken_StdinConflictsWithFlag(t *testing.T) {
	_, err := mcpRegistryGitHubToken(testCmdWithStdin("tok"), "pw", true)
	if err == nil {
		t.Fatal("--password and --password-stdin together must error")
	}
}

func TestMCPRegistryGitHubToken_NoTokenNoAppErrors(t *testing.T) {
	t.Setenv("VESSEL_GITHUB_CLIENT_ID", "")
	_, err := mcpRegistryGitHubToken(testCmdWithStdin(""), "", false)
	if err == nil {
		t.Fatal("no token and no OAuth app must error rather than run the device flow")
	}
	if !strings.Contains(err.Error(), "--password-stdin") {
		t.Errorf("error %q should point CI at --password-stdin", err.Error())
	}
}

func TestNonInteractiveCredentials_PasswordStdin(t *testing.T) {
	stdin := strings.NewReader("secret-token\n")
	user, pass, ok, err := nonInteractiveCredentials(stdin, "okedeji", "", true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Fatal("password-stdin with a username should be fully resolved")
	}
	if user != "okedeji" || pass != "secret-token" {
		t.Errorf("got (%q, %q), want (okedeji, secret-token)", user, pass)
	}
}

func TestNonInteractiveCredentials_PasswordStdinNeedsUsername(t *testing.T) {
	_, _, _, err := nonInteractiveCredentials(strings.NewReader("tok\n"), "", "", true)
	if err == nil {
		t.Fatal("--password-stdin without --username must error")
	}
	if !strings.Contains(err.Error(), "username") {
		t.Errorf("error %q should mention the missing username", err.Error())
	}
}

func TestNonInteractiveCredentials_PasswordStdinConflictsWithFlag(t *testing.T) {
	_, _, _, err := nonInteractiveCredentials(strings.NewReader("tok\n"), "okedeji", "pw", true)
	if err == nil {
		t.Fatal("--password and --password-stdin together must error")
	}
}

func TestNonInteractiveCredentials_BothFlags(t *testing.T) {
	user, pass, ok, err := nonInteractiveCredentials(strings.NewReader(""), "okedeji", "pw", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok || user != "okedeji" || pass != "pw" {
		t.Errorf("got (%q, %q, ok=%v), want (okedeji, pw, true)", user, pass, ok)
	}
}

func TestNonInteractiveCredentials_MissingNeedsPrompt(t *testing.T) {
	// ok=false with no error is the fall-through-to-prompt signal.
	_, _, ok, err := nonInteractiveCredentials(strings.NewReader(""), "", "", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Error("missing credentials should signal a prompt is needed (ok=false)")
	}
}
