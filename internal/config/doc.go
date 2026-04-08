// Package config is the single source of truth for all orchestrator
// configuration. Defaults() returns a complete *Config with safe
// values for every field; Load() merges an operator-supplied YAML
// override on top, field by field. Strict posture rejects dev
// affordances at load time so misconfigurations fail before any
// subsystem starts.
//
// Every fail-closed gate that lives elsewhere in the codebase reads
// its threshold from a posture-aware accessor on this package. Adding
// a new field means a default in Defaults(), an entry in the example
// YAML, and a merge test, in the same commit.
package config
