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
	"strings"
)

// BundleManifest is the JSON metadata stored inside a .cage bundle.
type BundleManifest struct {
	Name       string   `json:"name"`
	Version    string   `json:"version"`
	Runtime    string   `json:"runtime"`
	Entrypoint string   `json:"entrypoint"`
	SystemDeps []string `json:"system_deps,omitempty"`
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
func Pack(dir string, w io.Writer) (*BundleManifest, error) {
	cagefilePath := filepath.Join(dir, "Cagefile")
	f, err := os.Open(cagefilePath)
	if err != nil {
		return nil, fmt.Errorf("opening Cagefile in %s: %w", dir, err)
	}
	defer f.Close()

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
		Version:    "1.0.0",
		Runtime:    manifest.Runtime,
		Entrypoint: manifest.Entrypoint,
		SystemDeps: manifest.SystemDeps,
		PipDeps:    manifest.PipDeps,
		NpmDeps:    manifest.NpmDeps,
		GoDeps:     manifest.GoDeps,
		FilesHash:  "sha256:" + hash,
	}

	gw := gzip.NewWriter(w)
	defer gw.Close()

	tw := tar.NewWriter(gw)
	defer tw.Close()

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
func PackToFile(dir, outPath string) (*BundleManifest, error) {
	f, err := os.Create(outPath)
	if err != nil {
		return nil, fmt.Errorf("creating bundle file %s: %w", outPath, err)
	}
	defer f.Close()

	return Pack(dir, f)
}

// Unpack extracts a .cage bundle to a destination directory.
func Unpack(r io.Reader, destDir string) (*BundleManifest, error) {
	gr, err := gzip.NewReader(r)
	if err != nil {
		return nil, fmt.Errorf("opening gzip: %w", err)
	}
	defer gr.Close()

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
				out.Close()
				return nil, fmt.Errorf("extracting %s: %w", target, err)
			}
			out.Close()

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

// UnpackFile extracts a .cage file to a destination directory.
func UnpackFile(bundlePath, destDir string) (*BundleManifest, error) {
	f, err := os.Open(bundlePath)
	if err != nil {
		return nil, fmt.Errorf("opening bundle %s: %w", bundlePath, err)
	}
	defer f.Close()
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
