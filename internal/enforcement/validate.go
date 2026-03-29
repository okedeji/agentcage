package enforcement

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/okedeji/agentcage/internal/cage"
)

var ErrInvalidConfig = errors.New("invalid cage config")

const maxRequestsPerSecond int32 = 1000

var typeDurationLimits = map[cage.Type]time.Duration{
	cage.TypeDiscovery:  30 * time.Minute,
	cage.TypeValidator:  60 * time.Second,
	cage.TypeEscalation: 15 * time.Minute,
}

var typeVCPULimits = map[cage.Type]int32{
	cage.TypeDiscovery:  4,
	cage.TypeValidator:  1,
	cage.TypeEscalation: 2,
}

var typeMemoryLimits = map[cage.Type]int32{
	cage.TypeDiscovery:  8192,
	cage.TypeValidator:  1024,
	cage.TypeEscalation: 4096,
}

func ValidateCageConfig(config cage.Config) error {
	var errs []error

	errs = append(errs, validateScope(config.Scope)...)
	errs = append(errs, validateRateLimits(config.RateLimits)...)
	errs = append(errs, validateTimeLimits(config.Type, config.TimeLimits)...)
	errs = append(errs, validateResources(config.Type, config.Resources)...)
	errs = append(errs, validateRequiredFields(config)...)

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

func validateRateLimits(limits cage.RateLimits) []error {
	var errs []error
	if limits.RequestsPerSecond <= 0 {
		errs = append(errs, fmt.Errorf("rate limit must be positive, got %d", limits.RequestsPerSecond))
	}
	if limits.RequestsPerSecond > maxRequestsPerSecond {
		errs = append(errs, fmt.Errorf("rate limit must be ≤ %d, got %d", maxRequestsPerSecond, limits.RequestsPerSecond))
	}
	return errs
}

func validateTimeLimits(t cage.Type, limits cage.TimeLimits) []error {
	var errs []error
	if limits.MaxDuration <= 0 {
		errs = append(errs, fmt.Errorf("time limit must be positive, got %s", limits.MaxDuration))
		return errs
	}
	max, ok := typeDurationLimits[t]
	if ok && limits.MaxDuration > max {
		errs = append(errs, fmt.Errorf("%s cage time limit must be ≤ %s, got %s", t, max, limits.MaxDuration))
	}
	return errs
}

func validateResources(t cage.Type, res cage.ResourceLimits) []error {
	var errs []error
	if res.VCPUs <= 0 {
		errs = append(errs, fmt.Errorf("vCPUs must be positive, got %d", res.VCPUs))
	}
	if res.MemoryMB <= 0 {
		errs = append(errs, fmt.Errorf("memory must be positive, got %d MB", res.MemoryMB))
	}

	if maxVCPU, ok := typeVCPULimits[t]; ok && res.VCPUs > maxVCPU {
		errs = append(errs, fmt.Errorf("%s cage must use ≤ %d vCPU(s), got %d", t, maxVCPU, res.VCPUs))
	}
	if maxMem, ok := typeMemoryLimits[t]; ok && res.MemoryMB > maxMem {
		errs = append(errs, fmt.Errorf("%s cage must use ≤ %d MB memory, got %d", t, maxMem, res.MemoryMB))
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
