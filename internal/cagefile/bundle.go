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
	"strconv"
	"strings"
)

// BundleManifest is the JSON metadata stored inside a .cage bundle.
type BundleManifest struct {
	Name       string   `json:"name"`
	Version    string   `json:"version"`
	Runtime    string   `json:"runtime"`
	Entrypoint string   `json:"entrypoint"`
	SystemDeps []string `json:"system_deps,omitempty"`
	Packages   []string `json:"packages,omitempty"`
	PipDeps    []string `json:"pip_deps,omitempty"`
	NpmDeps    []string `json:"npm_deps,omitempty"`
	GoDeps     []string `json:"go_deps,omitempty"`
	FilesHash  string   `json:"files_hash"`
}

// Pack reads a directory containing a Cagefile and agent source, then writes
// a .cage bundle (gzipped tar) to the given writer.
//
// Bundle layout:
//
//	manifest.json
//	files/          (agent source code)
func Pack(dir string, version string, w io.Writer) (*BundleManifest, error) {
	cagefilePath := filepath.Join(dir, "Cagefile")
	f, err := os.Open(cagefilePath)
	if err != nil {
		return nil, fmt.Errorf("opening Cagefile in %s: %w", dir, err)
	}
	defer func() { _ = f.Close() }()

	manifest, err := Parse(f)
	if err != nil {
		return nil, fmt.Errorf("parsing Cagefile: %w", err)
	}

	// Compute hash of all agent files
	hash, err := hashDir(dir)
	if err != nil {
		return nil, fmt.Errorf("hashing agent files: %w", err)
	}

	bundleManifest := &BundleManifest{
		Name:       filepath.Base(dir),
		Version:    version,
		Runtime:    manifest.Runtime,
		Entrypoint: manifest.Entrypoint,
		SystemDeps: manifest.SystemDeps,
		Packages:   manifest.Packages,
		PipDeps:    manifest.PipDeps,
		NpmDeps:    manifest.NpmDeps,
		GoDeps:     manifest.GoDeps,
		FilesHash:  "sha256:" + hash,
	}

	gw := gzip.NewWriter(w)
	defer func() { _ = gw.Close() }()

	tw := tar.NewWriter(gw)
	defer func() { _ = tw.Close() }()

	// Write manifest.json
	manifestBytes, err := json.MarshalIndent(bundleManifest, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshaling manifest: %w", err)
	}

	if err := writeToTar(tw, "manifest.json", manifestBytes); err != nil {
		return nil, fmt.Errorf("writing manifest to bundle: %w", err)
	}

	// Write agent files under files/
	if err := addDirToTar(tw, dir, "files"); err != nil {
		return nil, fmt.Errorf("adding agent files to bundle: %w", err)
	}

	return bundleManifest, nil
}

// PackToFile packs a directory into a .cage file on disk.
func PackToFile(dir, version, outPath string) (*BundleManifest, error) {
	f, err := os.Create(outPath)
	if err != nil {
		return nil, fmt.Errorf("creating bundle file %s: %w", outPath, err)
	}
	defer func() { _ = f.Close() }()

	return Pack(dir, version, f)
}

// Unpack extracts a .cage bundle to a destination directory.
func Unpack(r io.Reader, destDir string) (*BundleManifest, error) {
	gr, err := gzip.NewReader(r)
	if err != nil {
		return nil, fmt.Errorf("opening gzip: %w", err)
	}
	defer func() { _ = gr.Close() }()

	tr := tar.NewReader(gr)

	var manifest *BundleManifest

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("reading tar entry: %w", err)
		}

		target := filepath.Join(destDir, header.Name)

		// Prevent path traversal
		if !strings.HasPrefix(filepath.Clean(target), filepath.Clean(destDir)+string(os.PathSeparator)) &&
			filepath.Clean(target) != filepath.Clean(destDir) {
			return nil, fmt.Errorf("invalid path in bundle: %s", header.Name)
		}

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0755); err != nil {
				return nil, fmt.Errorf("creating directory %s: %w", target, err)
			}

		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
				return nil, fmt.Errorf("creating parent for %s: %w", target, err)
			}

			out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(header.Mode))
			if err != nil {
				return nil, fmt.Errorf("creating file %s: %w", target, err)
			}

			if _, err := io.Copy(out, tr); err != nil {
				_ = out.Close()
				return nil, fmt.Errorf("extracting %s: %w", target, err)
			}
			_ = out.Close()

			// Parse manifest
			if header.Name == "manifest.json" {
				data, readErr := os.ReadFile(target)
				if readErr != nil {
					return nil, fmt.Errorf("reading extracted manifest: %w", readErr)
				}
				manifest = &BundleManifest{}
				if jsonErr := json.Unmarshal(data, manifest); jsonErr != nil {
					return nil, fmt.Errorf("parsing manifest: %w", jsonErr)
				}
			}
		}
	}

	if manifest == nil {
		return nil, fmt.Errorf("bundle does not contain manifest.json")
	}

	return manifest, nil
}

// CheckCompatibility verifies the bundle was packed with a compatible agentcage version.
func CheckCompatibility(bundle *BundleManifest, currentVersion string) error {
	bundleMajor, err := majorVersion(bundle.Version)
	if err != nil {
		return fmt.Errorf("invalid bundle version %q: %w", bundle.Version, err)
	}
	currentMajor, err := majorVersion(currentVersion)
	if err != nil {
		return fmt.Errorf("invalid current version %q: %w", currentVersion, err)
	}
	if bundleMajor > currentMajor {
		return fmt.Errorf("bundle was packed with agentcage v%s (major %d) but this is v%s (major %d) — upgrade agentcage",
			bundle.Version, bundleMajor, currentVersion, currentMajor)
	}
	return nil
}

func majorVersion(v string) (int, error) {
	v = strings.TrimPrefix(v, "v")
	parts := strings.SplitN(v, ".", 2)
	return strconv.Atoi(parts[0])
}

// UnpackFile extracts a .cage file to a destination directory.
func UnpackFile(bundlePath, destDir string) (*BundleManifest, error) {
	f, err := os.Open(bundlePath)
	if err != nil {
		return nil, fmt.Errorf("opening bundle %s: %w", bundlePath, err)
	}
	defer func() { _ = f.Close() }()
	return Unpack(f, destDir)
}

func writeToTar(tw *tar.Writer, name string, data []byte) error {
	header := &tar.Header{
		Name: name,
		Size: int64(len(data)),
		Mode: 0644,
	}
	if err := tw.WriteHeader(header); err != nil {
		return err
	}
	_, err := tw.Write(data)
	return err
}

func addDirToTar(tw *tar.Writer, srcDir, prefix string) error {
	return filepath.Walk(srcDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip the Cagefile itself — it's represented by manifest.json
		if info.Name() == "Cagefile" && filepath.Dir(path) == srcDir {
			return nil
		}

		rel, err := filepath.Rel(srcDir, path)
		if err != nil {
			return err
		}

		tarPath := filepath.Join(prefix, rel)
		if tarPath == prefix {
			return nil
		}

		if info.IsDir() {
			header := &tar.Header{
				Name:     tarPath + "/",
				Typeflag: tar.TypeDir,
				Mode:     0755,
			}
			return tw.WriteHeader(header)
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("reading %s: %w", path, err)
		}

		header := &tar.Header{
			Name: tarPath,
			Size: int64(len(data)),
			Mode: int64(info.Mode()),
		}
		if err := tw.WriteHeader(header); err != nil {
			return err
		}
		_, err = tw.Write(data)
		return err
	})
}

// HashDir computes a SHA256 hash of all files in a directory.
func HashDir(dir string) (string, error) {
	return hashDir(dir)
}

func hashDir(dir string) (string, error) {
	h := sha256.New()

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		h.Write([]byte(rel))
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		h.Write(data)
		return nil
	})
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}
