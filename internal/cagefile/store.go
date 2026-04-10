package cagefile

import (
	"crypto/sha256"
	"encoding/hex"
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

	tmp := dest + ".tmp"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return "", fmt.Errorf("creating temp file %s: %w", tmp, err)
	}

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
