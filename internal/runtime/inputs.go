package runtime

import (
	"fmt"
)

// injectOperatorValues adds the operator's env overrides and secret values to
// one agent's container env, scoped to what the agent declares. An undeclared
// value is never injected, so one pool serves the whole run without a
// third-party sub-agent reading a secret meant for another. A declared secret
// or value-less ENV input with nothing supplied fails closed. It takes the
// declared inputs directly rather than the sealed manifest so it also works at
// build introspection, where no manifest exists yet.
func injectOperatorValues(agentEnv, declaredEnv map[string]string, declaredSecrets []string, opEnv, opSecrets map[string]string) error {
	for key, def := range declaredEnv {
		if v, ok := opEnv[key]; ok {
			agentEnv[key] = v
			continue
		}
		// An empty default marks a required input the image did not bake;
		// missing is fatal, not a silently absent var.
		if def == "" {
			return fmt.Errorf("declares required input %q but it was not provided: pass --env %s=VALUE", key, key)
		}
	}
	for _, name := range declaredSecrets {
		v, ok := opSecrets[name]
		if !ok {
			return fmt.Errorf("declares secret %q but it was not provided: pass --secret %s", name, name)
		}
		agentEnv[name] = v
	}
	return nil
}
