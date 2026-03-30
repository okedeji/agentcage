//go:build ignore

package main

import (
	"fmt"
	"os"
	"regexp"

	"gopkg.in/yaml.v3"
)

type config struct {
	CageTypes         map[string]cageTypeConfig  `yaml:"cage_types"`
	RateLimits        rateLimitsConfig           `yaml:"rate_limits"`
	ActivityTimeouts  map[string]string          `yaml:"activity_timeouts"`
	FalcoRules        map[string]any             `yaml:"falco_rules"`
	TripwirePolicies  map[string]any             `yaml:"tripwire_policies"`
	BlocklistPatterns map[string][]patternEntry  `yaml:"blocklist_patterns"`
	Infrastructure    infrastructureConfig       `yaml:"infrastructure"`
}

type cageTypeConfig struct {
	MaxDuration string `yaml:"max_duration"`
	MaxVCPUs    int32  `yaml:"max_vcpus"`
	MaxMemoryMB int32  `yaml:"max_memory_mb"`
}

type rateLimitsConfig struct {
	MaxRequestsPerSecond int32 `yaml:"max_requests_per_second"`
}

type patternEntry struct {
	Pattern string `yaml:"pattern"`
	Message string `yaml:"message"`
}

type infrastructureConfig struct {
	GatewayAddr string   `yaml:"gateway_addr"`
	NATSAddr    string   `yaml:"nats_addr"`
	InfraHosts  []string `yaml:"infra_hosts"`
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

	// Required sections
	if len(cfg.CageTypes) == 0 {
		errs = append(errs, "cage_types section is empty or missing")
	}
	if cfg.RateLimits.MaxRequestsPerSecond <= 0 {
		errs = append(errs, "rate_limits.max_requests_per_second must be positive")
	}
	if len(cfg.ActivityTimeouts) == 0 {
		errs = append(errs, "activity_timeouts section is empty or missing")
	}
	if len(cfg.FalcoRules) == 0 {
		errs = append(errs, "falco_rules section is empty or missing")
	}
	if len(cfg.TripwirePolicies) == 0 {
		errs = append(errs, "tripwire_policies section is empty or missing")
	}
	if len(cfg.BlocklistPatterns) == 0 {
		errs = append(errs, "blocklist_patterns section is empty or missing")
	}
	if len(cfg.Infrastructure.InfraHosts) == 0 {
		errs = append(errs, "infrastructure.infra_hosts is empty or missing")
	}

	// Validate cage types have limits
	for name, ct := range cfg.CageTypes {
		if ct.MaxDuration == "" {
			errs = append(errs, fmt.Sprintf("cage_types.%s.max_duration is missing", name))
		}
		if ct.MaxVCPUs <= 0 {
			errs = append(errs, fmt.Sprintf("cage_types.%s.max_vcpus must be positive", name))
		}
		if ct.MaxMemoryMB <= 0 {
			errs = append(errs, fmt.Sprintf("cage_types.%s.max_memory_mb must be positive", name))
		}
	}

	// Validate activity timeouts are present (non-empty string means parseable by Go duration)
	requiredTimeouts := []string{
		"validate_scope", "issue_identity", "fetch_secrets", "provision_vm",
		"apply_policy", "start_agent", "export_audit_log", "teardown_vm",
		"revoke_svid", "revoke_vault_token", "verify_cleanup",
		"heartbeat_provision_vm", "heartbeat_monitor_cage",
	}
	for _, name := range requiredTimeouts {
		v, ok := cfg.ActivityTimeouts[name]
		if !ok || v == "" {
			errs = append(errs, fmt.Sprintf("activity_timeouts.%s is missing", name))
		}
	}

	// Validate blocklist patterns compile as valid regex
	for vulnClass, patterns := range cfg.BlocklistPatterns {
		for i, p := range patterns {
			if _, err := regexp.Compile(p.Pattern); err != nil {
				errs = append(errs, fmt.Sprintf("blocklist_patterns.%s[%d]: invalid regex %q: %v", vulnClass, i, p.Pattern, err))
			}
			if p.Message == "" {
				errs = append(errs, fmt.Sprintf("blocklist_patterns.%s[%d]: empty message", vulnClass, i))
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
