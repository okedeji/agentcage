package enforcement

import (
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/okedeji/agentcage/internal/cage"
	"github.com/okedeji/agentcage/internal/config"
)

var ErrInvalidConfig = errors.New("invalid cage config")

func ValidateCageConfig(cageConfig cage.Config, limits *config.Config) error {
	var errs []error

	errs = append(errs, validateScope(cageConfig.Scope)...)
	errs = append(errs, validateRateLimits(cageConfig.RateLimits, limits.RateLimit(cageConfig.Type.String()))...)

	typeLimits, hasType := limits.Cages[cageConfig.Type.String()]
	errs = append(errs, validateTimeLimits(cageConfig.Type, cageConfig.TimeLimits, hasType, typeLimits)...)
	errs = append(errs, validateResources(cageConfig.Type, cageConfig.Resources, hasType, typeLimits)...)
	errs = append(errs, validateRequiredFields(cageConfig)...)

	if len(errs) > 0 {
		return fmt.Errorf("%w: %w", ErrInvalidConfig, errors.Join(errs...))
	}
	return nil
}

func validateScope(scope cage.Scope) []error {
	var errs []error

	if len(scope.Hosts) == 0 {
		errs = append(errs, fmt.Errorf("scope must contain at least one host"))
		return errs
	}

	for _, host := range scope.Hosts {
		if host == "" {
			errs = append(errs, fmt.Errorf("scope host must not be empty"))
			continue
		}
		if strings.Contains(host, "*") {
			errs = append(errs, fmt.Errorf("scope host %q must not contain wildcard", host))
			continue
		}

		ip := net.ParseIP(host)
		if ip == nil {
			continue
		}
		if ip.IsLoopback() {
			errs = append(errs, fmt.Errorf("scope host %q is a loopback address", host))
			continue
		}
		if isPrivateIP(ip) {
			errs = append(errs, fmt.Errorf("scope host %q is a private IP address", host))
		}
	}

	for _, host := range scope.Hosts {
		lower := strings.ToLower(host)
		if lower == "localhost" {
			errs = append(errs, fmt.Errorf("scope host %q is a loopback address", host))
		}
	}

	return errs
}

var privateRanges = []net.IPNet{
	{IP: net.IP{10, 0, 0, 0}, Mask: net.CIDRMask(8, 32)},
	{IP: net.IP{172, 16, 0, 0}, Mask: net.CIDRMask(12, 32)},
	{IP: net.IP{192, 168, 0, 0}, Mask: net.CIDRMask(16, 32)},
}

func isPrivateIP(ip net.IP) bool {
	for _, r := range privateRanges {
		if r.Contains(ip) {
			return true
		}
	}
	return false
}

func validateRateLimits(limits cage.RateLimits, maxRPS int32) []error {
	var errs []error
	if limits.RequestsPerSecond <= 0 {
		errs = append(errs, fmt.Errorf("rate limit must be positive, got %d", limits.RequestsPerSecond))
	}
	if limits.RequestsPerSecond > maxRPS {
		errs = append(errs, fmt.Errorf("rate limit must be ≤ %d, got %d", maxRPS, limits.RequestsPerSecond))
	}
	return errs
}

func validateTimeLimits(t cage.Type, limits cage.TimeLimits, hasType bool, typeCfg config.CageTypeConfig) []error {
	var errs []error
	if limits.MaxDuration <= 0 {
		errs = append(errs, fmt.Errorf("time limit must be positive, got %s", limits.MaxDuration))
		return errs
	}
	if hasType && limits.MaxDuration > typeCfg.MaxDuration {
		errs = append(errs, fmt.Errorf("%s cage time limit must be ≤ %s, got %s", t, typeCfg.MaxDuration, limits.MaxDuration))
	}
	return errs
}

func validateResources(t cage.Type, res cage.ResourceLimits, hasType bool, typeCfg config.CageTypeConfig) []error {
	var errs []error
	if res.VCPUs <= 0 {
		errs = append(errs, fmt.Errorf("vCPUs must be positive, got %d", res.VCPUs))
	}
	if res.MemoryMB <= 0 {
		errs = append(errs, fmt.Errorf("memory must be positive, got %d MB", res.MemoryMB))
	}

	if hasType && res.VCPUs > typeCfg.MaxVCPUs {
		errs = append(errs, fmt.Errorf("%s cage must use ≤ %d vCPU(s), got %d", t, typeCfg.MaxVCPUs, res.VCPUs))
	}
	if hasType && res.MemoryMB > typeCfg.MaxMemoryMB {
		errs = append(errs, fmt.Errorf("%s cage must use ≤ %d MB memory, got %d", t, typeCfg.MaxMemoryMB, res.MemoryMB))
	}
	return errs
}

func validateRequiredFields(config cage.Config) []error {
	var errs []error
	switch config.Type {
	case cage.TypeValidator:
		if config.ParentFindingID == "" {
			errs = append(errs, fmt.Errorf("validator cage requires ParentFindingID"))
		}
	case cage.TypeDiscovery:
		if config.LLM == nil {
			errs = append(errs, fmt.Errorf("discovery cage requires LLM configuration"))
		}
	case cage.TypeEscalation:
		if config.ParentFindingID == "" {
			errs = append(errs, fmt.Errorf("escalation cage requires ParentFindingID"))
		}
	}
	return errs
}
