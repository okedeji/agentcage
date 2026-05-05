package cagefile

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// TagStore maps human-readable names (e.g. "agent-starter:latest") to
// content-addressed bundle refs. Backed by a JSON file on disk.
type TagStore struct {
	path string
	mu   sync.Mutex
}

func NewTagStore(path string) *TagStore {
	return &TagStore{path: path}
}

// Tag creates or moves a tag to point at the given ref.
func (ts *TagStore) Tag(name string, ref string) error {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	tags, err := ts.read()
	if err != nil {
		return fmt.Errorf("reading tag store: %w", err)
	}

	tags[name] = ref
	return ts.write(tags)
}

// Resolve accepts a name:tag, bare name (implies :latest), or hex ref
// prefix and returns the full bundle ref.
func (ts *TagStore) Resolve(query string) (string, error) {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	tags, err := ts.read()
	if err != nil {
		return "", fmt.Errorf("reading tag store: %w", err)
	}

	if strings.Contains(query, ":") {
		ref, ok := tags[query]
		if !ok {
			return "", fmt.Errorf("tag %q not found", query)
		}
		return ref, nil
	}

	// Bare name implies :latest.
	ref, ok := tags[query+":latest"]
	if !ok {
		return "", fmt.Errorf("tag %q not found", query+":latest")
	}
	return ref, nil
}

// List returns all tags as name→ref.
func (ts *TagStore) List() (map[string]string, error) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	return ts.read()
}

// Untag removes a tag.
func (ts *TagStore) Untag(name string) error {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	tags, err := ts.read()
	if err != nil {
		return fmt.Errorf("reading tag store: %w", err)
	}

	if _, ok := tags[name]; !ok {
		return fmt.Errorf("tag %q not found", name)
	}

	delete(tags, name)
	return ts.write(tags)
}

// TagsForRef returns all tag names that point to the given ref.
func (ts *TagStore) TagsForRef(ref string) []string {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	tags, _ := ts.read()
	var result []string
	for name, r := range tags {
		if r == ref {
			result = append(result, name)
		}
	}
	return result
}

func (ts *TagStore) read() (map[string]string, error) {
	data, err := os.ReadFile(ts.path)
	if err != nil {
		if os.IsNotExist(err) {
			return make(map[string]string), nil
		}
		return nil, err
	}

	tags := make(map[string]string)
	if err := json.Unmarshal(data, &tags); err != nil {
		return nil, fmt.Errorf("parsing tag store %s: %w", ts.path, err)
	}
	return tags, nil
}

func (ts *TagStore) write(tags map[string]string) error {
	if err := os.MkdirAll(filepath.Dir(ts.path), 0755); err != nil {
		return fmt.Errorf("creating tag store directory: %w", err)
	}

	data, err := json.MarshalIndent(tags, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling tags: %w", err)
	}

	tmp := ts.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		return fmt.Errorf("writing tag store: %w", err)
	}
	if err := os.Rename(tmp, ts.path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("finalizing tag store: %w", err)
	}
	return nil
}
