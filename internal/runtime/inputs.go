package runtime

import (
	"fmt"

	"github.com/okedeji/agentcage/internal/bundle"
)

// injectOperatorValues adds the operator's env overrides and secret values to
// one agent's container env, scoped to what that agent declares: only an ENV
// key or SECRETS name in the agent's own manifest is injected. An agent never
// receives a value it did not declare, so the operator can supply one pool for
// the whole run without a third-party sub-agent reading a secret meant for
// another. A declared secret, or a value-less ENV input, with no value supplied
// is a fail-closed error, since the agent asked for it and cannot work without
// it.
func injectOperatorValues(agentEnv map[string]string, m *bundle.Manifest, opEnv, opSecrets map[string]string) error {
	if m == nil {
		return nil
	}
	for key, def := range m.Agentfile.Env {
		if v, ok := opEnv[key]; ok {
			agentEnv[key] = v
			continue
		}
		// An empty default marks a required input the image did not bake, so a
		// missing operator value is fatal rather than a silently absent var.
		if def == "" {
			return fmt.Errorf("declares required input %q but it was not provided: pass --env %s=VALUE", key, key)
		}
	}
	for _, name := range m.Agentfile.Secrets {
		v, ok := opSecrets[name]
		if !ok {
			return fmt.Errorf("declares secret %q but it was not provided: pass --secret %s", name, name)
		}
		agentEnv[name] = v
	}
	return nil
}
