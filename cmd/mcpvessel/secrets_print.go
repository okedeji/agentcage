package main

import (
	"sort"
	"strings"
)

// formatSecretGrants renders one agent's declared secrets against the pool
// it will draw from: granted, or not granted (fatal at boot unless the
// declaration is optional). Names only, never values. This is the secrets
// counterpart of the egress report: the operator sees exactly which
// credentials will enter the cage before it boots.
func formatSecretGrants(declared, optional []string, pool map[string]string) string {
	if len(declared) == 0 {
		return "none declared"
	}
	isOptional := make(map[string]bool, len(optional))
	for _, name := range optional {
		isOptional[name] = true
	}
	names := append([]string(nil), declared...)
	sort.Strings(names)
	parts := make([]string, 0, len(names))
	for _, name := range names {
		switch {
		case pool[name] != "":
			parts = append(parts, name+" (granted)")
		case isOptional[name]:
			parts = append(parts, name+" (optional, not granted)")
		default:
			parts = append(parts, name+" (missing; pass --secret "+name+")")
		}
	}
	return strings.Join(parts, ", ")
}
