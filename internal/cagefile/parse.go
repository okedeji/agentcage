package cagefile

import (
	"bufio"
	"fmt"
	"io"
	"strings"
)

// Supported runtimes for cage agents.
var SupportedRuntimes = map[string]bool{
	"python3": true,
	"node":    true,
	"go":      true,
	"static":  true,
}

// SupportedTools is derived from ToolPackages — the single source of truth
// for what the base cage rootfs ships.
var SupportedTools = func() map[string]bool {
	m := make(map[string]bool, len(ToolPackages))
	for tool := range ToolPackages {
		m[tool] = true
	}
	return m
}()

// Manifest is the parsed representation of a Cagefile.
type Manifest struct {
	Runtime    string   `json:"runtime"`
	Entrypoint string   `json:"entrypoint"`
	SystemDeps []string `json:"system_deps,omitempty"`
	Packages   []string `json:"packages,omitempty"`
	PipDeps    []string `json:"pip_deps,omitempty"`
	NpmDeps    []string `json:"npm_deps,omitempty"`
	GoDeps     []string `json:"go_deps,omitempty"`
}

// Parse reads a Cagefile from the given reader and returns a Manifest.
//
// Cagefile format:
//
//	runtime python3
//	deps chromium nmap sqlmap
//	pip requests playwright httpx
//	npm puppeteer
//	entrypoint python3 solver.py
func Parse(r io.Reader) (*Manifest, error) {
	m := &Manifest{}
	scanner := bufio.NewScanner(r)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, " ", 2)
		if len(parts) < 2 {
			return nil, fmt.Errorf("line %d: directive %q requires a value", lineNum, parts[0])
		}

		directive := strings.ToLower(parts[0])
		value := strings.TrimSpace(parts[1])

		switch directive {
		case "runtime":
			if m.Runtime != "" {
				return nil, fmt.Errorf("line %d: duplicate runtime directive", lineNum)
			}
			if !SupportedRuntimes[value] {
				return nil, fmt.Errorf("line %d: unsupported runtime %q (supported: python3, node, go, static)", lineNum, value)
			}
			m.Runtime = value

		case "entrypoint":
			if m.Entrypoint != "" {
				return nil, fmt.Errorf("line %d: duplicate entrypoint directive", lineNum)
			}
			m.Entrypoint = value

		case "deps":
			deps := strings.Fields(value)
			for _, d := range deps {
				if !SupportedTools[d] {
					return nil, fmt.Errorf("line %d: unsupported system dependency %q", lineNum, d)
				}
			}
			m.SystemDeps = append(m.SystemDeps, deps...)

		case "packages":
			m.Packages = append(m.Packages, strings.Fields(value)...)

		case "pip":
			m.PipDeps = append(m.PipDeps, strings.Fields(value)...)

		case "npm":
			m.NpmDeps = append(m.NpmDeps, strings.Fields(value)...)

		case "go-deps":
			m.GoDeps = append(m.GoDeps, strings.Fields(value)...)

		default:
			return nil, fmt.Errorf("line %d: unknown directive %q", lineNum, directive)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading Cagefile: %w", err)
	}

	return m, m.validate()
}

// ParseString is a convenience wrapper for parsing a Cagefile from a string.
func ParseString(s string) (*Manifest, error) {
	return Parse(strings.NewReader(s))
}

func (m *Manifest) validate() error {
	if m.Runtime == "" {
		return fmt.Errorf("cagefile: runtime is required")
	}
	if m.Entrypoint == "" {
		return fmt.Errorf("cagefile: entrypoint is required")
	}

	switch m.Runtime {
	case "python3":
		if len(m.NpmDeps) > 0 {
			return fmt.Errorf("cagefile: npm dependencies are not valid for python3 runtime")
		}
		if len(m.GoDeps) > 0 {
			return fmt.Errorf("cagefile: go-deps are not valid for python3 runtime")
		}
	case "node":
		if len(m.PipDeps) > 0 {
			return fmt.Errorf("cagefile: pip dependencies are not valid for node runtime")
		}
		if len(m.GoDeps) > 0 {
			return fmt.Errorf("cagefile: go-deps are not valid for node runtime")
		}
	case "go":
		if len(m.PipDeps) > 0 {
			return fmt.Errorf("cagefile: pip dependencies are not valid for go runtime")
		}
		if len(m.NpmDeps) > 0 {
			return fmt.Errorf("cagefile: npm dependencies are not valid for go runtime")
		}
	case "static":
		if len(m.PipDeps) > 0 || len(m.NpmDeps) > 0 || len(m.GoDeps) > 0 {
			return fmt.Errorf("cagefile: language dependencies are not valid for static runtime")
		}
	}

	return nil
}
