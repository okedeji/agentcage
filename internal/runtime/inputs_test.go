package runtime

import (
	"testing"
)

func TestInjectOperatorValues_ScopesToDeclaredNames(t *testing.T) {
	agentEnv := map[string]string{}
	declaredEnv := map[string]string{"LOG_LEVEL": "info"}
	declaredSecrets := []string{"notion_token"}
	opEnv := map[string]string{"LOG_LEVEL": "debug", "OTHER": "nope"}
	opSecrets := map[string]string{"notion_token": "ntn-secret", "elsewhere": "nope"}

	if err := injectOperatorValues(agentEnv, declaredEnv, declaredSecrets, nil, opEnv, opSecrets); err != nil {
		t.Fatalf("inject: %v", err)
	}
	if agentEnv["LOG_LEVEL"] != "debug" {
		t.Errorf("declared ENV not overridden: %q", agentEnv["LOG_LEVEL"])
	}
	if agentEnv["notion_token"] != "ntn-secret" {
		t.Errorf("declared secret not injected: %q", agentEnv["notion_token"])
	}
	// A name the agent did not declare is never injected, even though the
	// operator pool has it.
	if _, leaked := agentEnv["OTHER"]; leaked {
		t.Error("an undeclared env key leaked into the agent")
	}
	if _, leaked := agentEnv["elsewhere"]; leaked {
		t.Error("an undeclared secret leaked into the agent")
	}
}

func TestInjectOperatorValuesSplit_SecretsGoToSecretEnv(t *testing.T) {
	// The split variant keeps secret values out of the plain env map (which
	// becomes argv) and in the secret map (which the runtime pipes off argv),
	// while ENV overrides still land in the plain map.
	agentEnv := map[string]string{}
	secretEnv := map[string]string{}
	declaredEnv := map[string]string{"LOG_LEVEL": "info"}
	if err := injectOperatorValuesSplit(agentEnv, secretEnv, declaredEnv,
		[]string{"github_token"}, nil,
		map[string]string{"LOG_LEVEL": "debug"},
		map[string]string{"github_token": "ghp-secret"}); err != nil {
		t.Fatalf("inject: %v", err)
	}
	if agentEnv["LOG_LEVEL"] != "debug" {
		t.Errorf("env override not in plain map: %q", agentEnv["LOG_LEVEL"])
	}
	if _, onArgv := agentEnv["github_token"]; onArgv {
		t.Error("secret value landed in the plain (argv) env map")
	}
	if secretEnv["github_token"] != "ghp-secret" {
		t.Errorf("secret not routed to secretEnv: %q", secretEnv["github_token"])
	}
}

func TestInjectOperatorValues_MissingDeclaredSecretFailsClosed(t *testing.T) {
	err := injectOperatorValues(map[string]string{}, nil, []string{"required_key"}, nil, nil, nil)
	if err == nil {
		t.Fatal("expected a fail-closed error for a declared secret with no value")
	}
}

func TestInjectOperatorValues_OptionalSecret(t *testing.T) {
	// An optional secret is injected when supplied and simply absent, not an
	// error, when not.
	agentEnv := map[string]string{}
	if err := injectOperatorValues(agentEnv, nil, []string{"github_token"}, []string{"github_token"},
		nil, map[string]string{"github_token": "ghp-x"}); err != nil {
		t.Fatalf("optional secret supplied: %v", err)
	}
	if agentEnv["github_token"] != "ghp-x" {
		t.Errorf("optional secret not injected when supplied: %q", agentEnv["github_token"])
	}
	// Absent is fine, no error.
	if err := injectOperatorValues(map[string]string{}, nil, []string{"github_token"}, []string{"github_token"}, nil, nil); err != nil {
		t.Errorf("optional secret should not fail closed when absent: %v", err)
	}
}

func TestInjectOperatorValues_RequiredEnvInput(t *testing.T) {
	// An empty default is a required input: it injects when supplied and fails
	// closed when not, while a key with a real default is left to the image.
	declaredEnv := map[string]string{"SYSTEM_PROMPT": "", "LOG_LEVEL": "info"}

	agentEnv := map[string]string{}
	if err := injectOperatorValues(agentEnv, declaredEnv, nil, nil, map[string]string{"SYSTEM_PROMPT": "be terse"}, nil); err != nil {
		t.Fatalf("inject with required value supplied: %v", err)
	}
	if agentEnv["SYSTEM_PROMPT"] != "be terse" {
		t.Errorf("required input not injected: %q", agentEnv["SYSTEM_PROMPT"])
	}
	// LOG_LEVEL has a baked default, so a missing operator value is not injected
	// here and is not an error.
	if _, ok := agentEnv["LOG_LEVEL"]; ok {
		t.Error("a defaulted ENV should be left to the image, not injected")
	}

	if err := injectOperatorValues(map[string]string{}, declaredEnv, nil, nil, nil, nil); err == nil {
		t.Fatal("expected a fail-closed error for a required input with no value")
	}
}
