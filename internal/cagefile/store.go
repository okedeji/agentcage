package cagefile

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// Keyed by SHA256 so the same agent packed twice is deduplicated.
type BundleStore struct {
	dir string
}

func NewBundleStore(dir string) (*BundleStore, error) {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("creating bundle store %s: %w", dir, err)
	}
	return &BundleStore{dir: dir}, nil
}

func (s *BundleStore) Store(cagePath string) (string, error) {
	hash, err := hashFile(cagePath)
	if err != nil {
		return "", fmt.Errorf("hashing bundle %s: %w", cagePath, err)
	}

	dest := s.Path(hash)
	if _, err := os.Stat(dest); err == nil {
		return hash, nil
	}

	src, err := os.Open(cagePath)
	if err != nil {
		return "", fmt.Errorf("opening bundle %s: %w", cagePath, err)
	}
	defer func() { _ = src.Close() }()

	out, err := os.CreateTemp(s.dir, ".store-*.tmp")
	if err != nil {
		return "", fmt.Errorf("creating temp file in %s: %w", s.dir, err)
	}
	tmp := out.Name()

	if _, err := io.Copy(out, src); err != nil {
		_ = out.Close()
		_ = os.Remove(tmp)
		return "", fmt.Errorf("copying bundle: %w", err)
	}
	if err := out.Close(); err != nil {
		_ = os.Remove(tmp)
		return "", fmt.Errorf("closing temp file: %w", err)
	}
	if err := os.Rename(tmp, dest); err != nil {
		_ = os.Remove(tmp)
		return "", fmt.Errorf("finalizing bundle: %w", err)
	}

	return hash, nil
}

func (s *BundleStore) Path(ref string) string {
	return filepath.Join(s.dir, ref+".cage")
}

func (s *BundleStore) Exists(ref string) bool {
	_, err := os.Stat(s.Path(ref))
	return err == nil
}

// Resolve expands a short ref prefix to the full ref. Scans the store
// directory for a .cage file whose name starts with the prefix.
func (s *BundleStore) Resolve(prefix string) (string, error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return "", fmt.Errorf("reading bundle store: %w", err)
	}

	var match string
	for _, e := range entries {
		name := e.Name()
		if !hasSuffix(name, ".cage") {
			continue
		}
		ref := name[:len(name)-5]
		if hasPrefix(ref, prefix) {
			if match != "" {
				return "", fmt.Errorf("ambiguous ref %s (matches %s and %s)", prefix, match[:12], ref[:12])
			}
			match = ref
		}
	}
	if match == "" {
		return "", fmt.Errorf("no bundle matches ref %s", prefix)
	}
	return match, nil
}

func hasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}

func hasSuffix(s, suffix string) bool {
	return len(s) >= len(suffix) && s[len(s)-len(suffix):] == suffix
}

// ReadManifestFromBundle reads manifest.json from a .cage tar.gz
// without extracting all files. Used for listing agents.
func ReadManifestFromBundle(r io.Reader) (*BundleManifest, error) {
	gr, err := gzip.NewReader(r)
	if err != nil {
		return nil, err
	}
	defer func() { _ = gr.Close() }()

	tr := tar.NewReader(gr)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil, fmt.Errorf("manifest.json not found in bundle")
		}
		if err != nil {
			return nil, err
		}
		if hdr.Name == "manifest.json" {
			var m BundleManifest
			if err := json.NewDecoder(tr).Decode(&m); err != nil {
				return nil, fmt.Errorf("decoding manifest.json: %w", err)
			}
			return &m, nil
		}
	}
}

func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
