//go:build ignore

package main

import (
	"fmt"
	"os"
	"regexp"

	"gopkg.in/yaml.v3"
)

type config struct {
	Cages      map[string]cageTypeConfig  `yaml:"cages"`
	Assessment assessmentConfig           `yaml:"assessment"`
	Scope      scopeConfig                `yaml:"scope"`
	Payload    map[string]payloadConfig   `yaml:"payload"`
	Monitoring map[string]monitoringConfig `yaml:"monitoring"`
	LLM        llmConfig                  `yaml:"llm"`
}

type cageTypeConfig struct {
	MaxDuration string `yaml:"max_duration"`
	MaxVCPUs    int32  `yaml:"max_vcpus"`
	MaxMemoryMB int32  `yaml:"max_memory_mb"`
	RateLimit   int32  `yaml:"rate_limit"`
}

type assessmentConfig struct {
	MaxDuration   string `yaml:"max_duration"`
	TokenBudget   int64  `yaml:"token_budget"`
	MaxIterations int32  `yaml:"max_iterations"`
	ReviewTimeout string `yaml:"review_timeout"`
}

type scopeConfig struct {
	Deny          []string `yaml:"deny"`
	DenyWildcards bool     `yaml:"deny_wildcards"`
	DenyLocalhost bool     `yaml:"deny_localhost"`
}

type payloadConfig struct {
	Block []patternEntry `yaml:"block"`
}

type patternEntry struct {
	Pattern string `yaml:"pattern"`
	Reason  string `yaml:"reason"`
}

type monitoringConfig struct {
	Rules         map[string]monitoringRule `yaml:"rules"`
	DefaultAction string                    `yaml:"default_action"`
}

type monitoringRule struct {
	Detect string `yaml:"detect"`
	Action string `yaml:"action"`
}

type llmConfig struct {
	Endpoint  string `yaml:"endpoint"`
	APIKeyEnv string `yaml:"api_key_env"`
}

func main() {
	data, err := os.ReadFile("agentcage.yaml")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: reading agentcage.yaml: %v\n", err)
		os.Exit(1)
	}

	var cfg config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		fmt.Fprintf(os.Stderr, "error: parsing agentcage.yaml: %v\n", err)
		os.Exit(1)
	}

	var errs []string

	if len(cfg.Cages) == 0 {
		errs = append(errs, "cages section is empty or missing")
	}
	if len(cfg.Scope.Deny) == 0 {
		errs = append(errs, "scope.deny is empty or missing")
	}
	if len(cfg.Payload) == 0 {
		errs = append(errs, "payload section is empty or missing")
	}
	if len(cfg.Monitoring) == 0 {
		errs = append(errs, "monitoring section is empty or missing")
	}

	for name, ct := range cfg.Cages {
		if ct.MaxDuration == "" {
			errs = append(errs, fmt.Sprintf("cages.%s.max_duration is missing", name))
		}
		if ct.MaxVCPUs <= 0 {
			errs = append(errs, fmt.Sprintf("cages.%s.max_vcpus must be positive", name))
		}
		if ct.MaxMemoryMB <= 0 {
			errs = append(errs, fmt.Sprintf("cages.%s.max_memory_mb must be positive", name))
		}
	}

	for vulnClass, pc := range cfg.Payload {
		for i, p := range pc.Block {
			if _, err := regexp.Compile(p.Pattern); err != nil {
				errs = append(errs, fmt.Sprintf("payload.%s.block[%d]: invalid regex %q: %v", vulnClass, i, p.Pattern, err))
			}
			if p.Reason == "" {
				errs = append(errs, fmt.Sprintf("payload.%s.block[%d]: empty reason", vulnClass, i))
			}
		}
	}

	validActions := map[string]bool{"log": true, "human_review": true, "kill": true}
	for cageType, mc := range cfg.Monitoring {
		if mc.DefaultAction != "" && !validActions[mc.DefaultAction] {
			errs = append(errs, fmt.Sprintf("monitoring.%s.default_action: invalid action %q", cageType, mc.DefaultAction))
		}
		for ruleName, rule := range mc.Rules {
			if rule.Detect == "" {
				errs = append(errs, fmt.Sprintf("monitoring.%s.rules.%s: detect is empty", cageType, ruleName))
			}
			if !validActions[rule.Action] {
				errs = append(errs, fmt.Sprintf("monitoring.%s.rules.%s: invalid action %q", cageType, ruleName, rule.Action))
			}
		}
	}

	if len(errs) > 0 {
		fmt.Fprintln(os.Stderr, "agentcage.yaml validation failed:")
		for _, e := range errs {
			fmt.Fprintf(os.Stderr, "  - %s\n", e)
		}
		os.Exit(1)
	}

	fmt.Println("agentcage.yaml: OK")
}
