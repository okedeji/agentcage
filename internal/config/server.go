package config

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

type Server struct {
	mu       sync.RWMutex
	base     *Config
	override *Config
	current  *Config
}

func NewServer(base *Config) *Server {
	return &Server{
		base:    base,
		current: base,
	}
}

func (s *Server) GetConfig(_ context.Context) *Config {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.current
}

func (s *Server) GetValue(_ context.Context, path string) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	tree, err := configToYAMLMap(s.current)
	if err != nil {
		return "", fmt.Errorf("marshaling config for path lookup: %w", err)
	}

	val, err := navigateYAMLMap(tree, path)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%v", val), nil
}

func (s *Server) UpdateValue(_ context.Context, path, value string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	tree, err := configToYAMLMap(s.current)
	if err != nil {
		return fmt.Errorf("marshaling config for update: %w", err)
	}

	if err := setYAMLMapValue(tree, path, value); err != nil {
		return fmt.Errorf("setting value at path %q: %w", path, err)
	}

	raw, err := yaml.Marshal(tree)
	if err != nil {
		return fmt.Errorf("re-marshaling config after update: %w", err)
	}

	updated, err := Parse(raw)
	if err != nil {
		return fmt.Errorf("parsing updated config: %w", err)
	}

	s.override = updated
	s.current = Merge(s.base, s.override)
	return nil
}

func (s *Server) ResetConfig(_ context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.override = nil
	s.current = s.base
	return nil
}

// Import replaces the entire override config. The base config is
// preserved; the imported config is merged on top.
func (s *Server) Import(_ context.Context, cfg *Config) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.override = cfg
	s.current = Merge(s.base, cfg)
}

// AddAPIKey appends an API key entry to the live config.
func (s *Server) AddAPIKey(_ context.Context, entry APIKeyEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, k := range s.current.Access.APIKeys {
		if k.Name == entry.Name {
			return fmt.Errorf("key with name %q already exists", entry.Name)
		}
	}

	s.current.Access.APIKeys = append(s.current.Access.APIKeys, entry)
	return nil
}

// RemoveAPIKey removes an API key by name from the live config.
func (s *Server) RemoveAPIKey(_ context.Context, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	var remaining []APIKeyEntry
	found := false
	for _, k := range s.current.Access.APIKeys {
		if k.Name == name {
			found = true
			continue
		}
		remaining = append(remaining, k)
	}
	if !found {
		return fmt.Errorf("no key found with name %q", name)
	}
	s.current.Access.APIKeys = remaining
	return nil
}

func configToYAMLMap(cfg *Config) (map[string]any, error) {
	raw, err := yaml.Marshal(cfg)
	if err != nil {
		return nil, fmt.Errorf("marshaling config to YAML: %w", err)
	}

	var tree map[string]any
	if err := yaml.Unmarshal(raw, &tree); err != nil {
		return nil, fmt.Errorf("unmarshaling config to map: %w", err)
	}

	return tree, nil
}

func navigateYAMLMap(tree map[string]any, path string) (any, error) {
	parts := strings.Split(path, ".")
	var current any = tree

	for i, part := range parts {
		m, ok := current.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("path %q: segment %q is not a map", path, strings.Join(parts[:i], "."))
		}
		val, ok := m[part]
		if !ok {
			return nil, fmt.Errorf("path %q: key %q not found", path, part)
		}
		current = val
	}

	return current, nil
}

func setYAMLMapValue(tree map[string]any, path, value string) error {
	parts := strings.Split(path, ".")
	var current any = tree

	for i, part := range parts[:len(parts)-1] {
		m, ok := current.(map[string]any)
		if !ok {
			return fmt.Errorf("segment %q is not a map", strings.Join(parts[:i], "."))
		}
		val, ok := m[part]
		if !ok {
			return fmt.Errorf("key %q not found", part)
		}
		current = val
	}

	m, ok := current.(map[string]any)
	if !ok {
		return fmt.Errorf("parent of %q is not a map", parts[len(parts)-1])
	}

	lastKey := parts[len(parts)-1]
	if _, ok := m[lastKey]; !ok {
		return fmt.Errorf("key %q not found", lastKey)
	}

	m[lastKey] = value
	return nil
}
