package runtime

import (
	"fmt"
	"sort"
	"strings"
)

// ScopedSecrets is the operator's secret pool, keyed by agent scope; "" is
// the broadcast pool every agent draws from. An agent's effective pool is
// the broadcast plus its own scope, the scoped value winning a name
// collision. Scopes let one run grant a secret to a single agent
// (--secret agent:NAME) instead of to every agent that declares its name,
// the same choice --egress gives for hosts.
type ScopedSecrets map[string]map[string]string

// For resolves one agent's effective pool: broadcast overlaid by its scope.
func (s ScopedSecrets) For(scope string) map[string]string {
	if len(s) == 0 {
		return nil
	}
	out := make(map[string]string, len(s[""])+len(s[scope]))
	for k, v := range s[""] {
		out[k] = v
	}
	if scope != "" {
		for k, v := range s[scope] {
			out[k] = v
		}
	}
	return out
}

// Flatten merges every scope into one pool, for boots with a single agent
// (introspection, eval) where scoping has nothing to distinguish.
func (s ScopedSecrets) Flatten() map[string]string {
	if len(s) == 0 {
		return nil
	}
	out := map[string]string{}
	for _, pool := range s {
		for k, v := range pool {
			out[k] = v
		}
	}
	return out
}

// Scopes lists the non-broadcast scope names, sorted, so a boot can flag a
// scope that matches no agent in the run instead of silently granting
// nothing.
func (s ScopedSecrets) Scopes() []string {
	var out []string
	for scope := range s {
		if scope != "" {
			out = append(out, scope)
		}
	}
	sort.Strings(out)
	return out
}

// Broadcast wraps a flat pool as an unscoped ScopedSecrets, for callers that
// have no scoping to express.
func Broadcast(pool map[string]string) ScopedSecrets {
	if len(pool) == 0 {
		return nil
	}
	return ScopedSecrets{"": pool}
}

// injectOperatorValues adds the operator's env overrides and secret values to
// one agent's container env, scoped to what the agent declares. An undeclared
// value is never injected, so one pool serves the whole run without a
// third-party sub-agent reading a secret meant for another. A declared secret
// or value-less ENV input with nothing supplied fails closed, unless it is in
// optional, in which case it is simply left absent. It takes the declared inputs
// directly rather than the sealed manifest so it also works at build
// introspection, where no manifest exists yet.
func injectOperatorValues(agentEnv, declaredEnv map[string]string, declaredSecrets, optional []string, opEnv, opSecrets map[string]string) error {
	// Secrets land in the same map as plain env, the legacy shape callers that
	// cannot separate the two (the attached root, whose env is passed straight
	// to nerdctl) still rely on.
	return injectOperatorValuesSplit(agentEnv, agentEnv, declaredEnv, declaredSecrets, optional, opEnv, opSecrets)
}

// injectOperatorValuesSplit is injectOperatorValues but routes secret values
// into secretEnv rather than agentEnv, so a caller can keep them off the
// container's argv (delivered via --env-file instead; see ContainerSpec.SecretEnv).
// The env-override and required/optional rules are identical. Pass the same map
// for both to fold secrets back in with the plain env.
func injectOperatorValuesSplit(agentEnv, secretEnv, declaredEnv map[string]string, declaredSecrets, optional []string, opEnv, opSecrets map[string]string) error {
	isOptional := make(map[string]bool, len(optional))
	for _, name := range optional {
		isOptional[name] = true
	}
	for key, def := range declaredEnv {
		if v, ok := opEnv[key]; ok {
			agentEnv[key] = v
			continue
		}
		// An empty default marks a required input the image did not bake;
		// missing is fatal, not a silently absent var, unless it is optional.
		if def == "" && !isOptional[key] {
			return fmt.Errorf("declares required input %q but it was not provided: pass --env %s=VALUE", key, key)
		}
	}
	for _, name := range declaredSecrets {
		v, ok := opSecrets[name]
		if !ok {
			if isOptional[name] {
				continue
			}
			return fmt.Errorf("declares secret %q but it was not provided: pass --secret %s", name, name)
		}
		// Secrets are delivered through a line-oriented env-file (--env-file
		// /dev/stdin); a value with an embedded newline would inject a second,
		// undeclared KEY=VALUE line into the cage (defeating declaration-gating
		// at the file layer) or silently truncate a multi-line value. Refuse it
		// loudly rather than corrupt or over-inject.
		if strings.ContainsAny(v, "\n\r") {
			return fmt.Errorf("secret %q contains a newline, which cannot be delivered as an env value; store it without embedded newlines", name)
		}
		secretEnv[name] = v
	}
	return nil
}
