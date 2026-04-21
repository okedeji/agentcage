package plan

import (
	"fmt"
	"strings"
	"time"

	"github.com/okedeji/agentcage/internal/config"
)

// Fields the plan file and CLI flags don't set fall back to the
// org's configured policy.
func BasePlanFromConfig(cfg *config.Config) *Plan {
	p := &Plan{
		Budget: Budget{
			Tokens: cfg.Assessment.TokenBudget,
		},
	}
	if cfg.Assessment.MaxDuration > 0 {
		p.Budget.MaxDuration = cfg.Assessment.MaxDuration.String()
	}

	if len(cfg.Cages) > 0 {
		p.CageTypes = make(map[string]CageType, len(cfg.Cages))
		for name, ct := range cfg.Cages {
			vcpus := ct.DefaultVCPUs
			if vcpus <= 0 {
				vcpus = ct.MaxVCPUs
			}
			mem := ct.DefaultMemoryMB
			if mem <= 0 {
				mem = ct.MaxMemoryMB
			}
			p.CageTypes[name] = CageType{
				VCPUs:         vcpus,
				MemoryMB:      mem,
				MaxConcurrent: ct.MaxConcurrent,
				MaxDuration:   ct.MaxDuration.String(),
			}
		}
	}

	// Escalation cage type defines the org default chain depth.
	if esc, ok := cfg.Cages["escalation"]; ok && esc.MaxChainDepth > 0 {
		p.Limits.MaxChainDepth = esc.MaxChainDepth
	}

	return p
}

// EnforceConfigCeilings rejects plan values that exceed the operator
// config's limits. Call after Merge so the final merged plan is
// checked against org policy.
func EnforceConfigCeilings(p *Plan, cfg *config.Config) error {
	if cfg.Assessment.TokenBudget > 0 && p.Budget.Tokens > cfg.Assessment.TokenBudget {
		return fmt.Errorf("token budget %d exceeds operator limit %d", p.Budget.Tokens, cfg.Assessment.TokenBudget)
	}

	if p.Budget.MaxDuration != "" && cfg.Assessment.MaxDuration > 0 {
		d, err := time.ParseDuration(p.Budget.MaxDuration)
		if err != nil {
			return fmt.Errorf("invalid max_duration %q: %w", p.Budget.MaxDuration, err)
		}
		if d > cfg.Assessment.MaxDuration {
			return fmt.Errorf("max duration %s exceeds operator limit %s", p.Budget.MaxDuration, cfg.Assessment.MaxDuration)
		}
	}

	if esc, ok := cfg.Cages["escalation"]; ok && esc.MaxChainDepth > 0 && p.Limits.MaxChainDepth > esc.MaxChainDepth {
		return fmt.Errorf("max_chain_depth %d exceeds operator limit %d", p.Limits.MaxChainDepth, esc.MaxChainDepth)
	}

	if cfg.Assessment.MaxIterations > 0 && p.Limits.MaxIterations > cfg.Assessment.MaxIterations {
		return fmt.Errorf("max_iterations %d exceeds operator limit %d", p.Limits.MaxIterations, cfg.Assessment.MaxIterations)
	}

	if cfg.Assessment.MaxConcurrent > 0 && p.Limits.MaxConcurrentCages > cfg.Assessment.MaxConcurrent {
		return fmt.Errorf("max_concurrent_cages %d exceeds operator limit %d", p.Limits.MaxConcurrentCages, cfg.Assessment.MaxConcurrent)
	}

	if cfg.Posture == config.PostureStrict && p.Notifications.Webhook != "" && strings.HasPrefix(p.Notifications.Webhook, "http://") {
		return fmt.Errorf("posture=strict: webhook %q uses plaintext HTTP, HTTPS required", p.Notifications.Webhook)
	}

	for name, ct := range p.CageTypes {
		cfgCt, ok := cfg.Cages[name]
		if !ok {
			continue
		}
		if ct.VCPUs > cfgCt.MaxVCPUs && cfgCt.MaxVCPUs > 0 {
			return fmt.Errorf("cage_types.%s.vcpus %d exceeds operator limit %d", name, ct.VCPUs, cfgCt.MaxVCPUs)
		}
		if ct.MemoryMB > cfgCt.MaxMemoryMB && cfgCt.MaxMemoryMB > 0 {
			return fmt.Errorf("cage_types.%s.memory_mb %d exceeds operator limit %d", name, ct.MemoryMB, cfgCt.MaxMemoryMB)
		}
		if ct.MaxConcurrent > cfgCt.MaxConcurrent && cfgCt.MaxConcurrent > 0 {
			return fmt.Errorf("cage_types.%s.max_concurrent %d exceeds operator limit %d", name, ct.MaxConcurrent, cfgCt.MaxConcurrent)
		}
		if ct.MaxDuration != "" && cfgCt.MaxDuration > 0 {
			d, err := time.ParseDuration(ct.MaxDuration)
			if err != nil {
				return fmt.Errorf("cage_types.%s: invalid max_duration %q: %w", name, ct.MaxDuration, err)
			}
			if d > cfgCt.MaxDuration {
				return fmt.Errorf("cage_types.%s.max_duration %s exceeds operator limit %s", name, ct.MaxDuration, cfgCt.MaxDuration)
			}
		}
	}

	return nil
}
