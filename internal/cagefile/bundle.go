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
	"sort"
	"strconv"
	"strings"
	"time"
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

	// Validate entrypoint script exists in the agent directory
	if err := validateEntrypointExists(dir, manifest.Entrypoint); err != nil {
		return nil, err
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

// DefaultMaxBundleSize is the default size limit for agent directories (2GB).
const DefaultMaxBundleSize int64 = 2 * 1024 * 1024 * 1024

// PackToFile packs a directory into a .cage file on disk.
// maxSize limits the total size of files in the directory. Pass 0 to use DefaultMaxBundleSize.
func PackToFile(dir, version, outPath string, maxSize int64) (*BundleManifest, error) {
	if maxSize <= 0 {
		maxSize = DefaultMaxBundleSize
	}

	size, err := DirSize(dir)
	if err != nil {
		return nil, fmt.Errorf("calculating directory size: %w", err)
	}
	if size > maxSize {
		return nil, fmt.Errorf("directory is %.1f MB, exceeds max bundle size %.1f MB — use --max-size to increase the limit",
			float64(size)/(1024*1024), float64(maxSize)/(1024*1024))
	}

	f, err := os.Create(outPath)
	if err != nil {
		return nil, fmt.Errorf("creating bundle file %s: %w", outPath, err)
	}
	defer func() { _ = f.Close() }()

	return Pack(dir, version, f)
}

// DirSize returns the total size of all files in a directory tree.
func DirSize(dir string) (int64, error) {
	var total int64
	err := filepath.Walk(dir, func(_ string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		total += info.Size()
		return nil
	})
	return total, err
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
		case tar.TypeSymlink, tar.TypeLink, tar.TypeChar, tar.TypeBlock, tar.TypeFifo:
			return nil, fmt.Errorf("rejected unsafe entry in bundle: %s (type %d)", header.Name, header.Typeflag)

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
	if bundleMajor != currentMajor {
		return fmt.Errorf("bundle was packed with agentcage v%s (major %d) but this is v%s (major %d) — major version mismatch",
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
		Name:    name,
		Size:    int64(len(data)),
		Mode:    0644,
		ModTime: time.Now(),
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

		// Reject symlinks — they could reference files outside the agent directory
		linfo, lstatErr := os.Lstat(path)
		if lstatErr != nil {
			return fmt.Errorf("stat %s: %w", path, lstatErr)
		}
		if linfo.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("symlinks not allowed in agent directory: %s", path)
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
				ModTime:  info.ModTime(),
			}
			return tw.WriteHeader(header)
		}

		header := &tar.Header{
			Name:    tarPath,
			Size:    info.Size(),
			Mode:    int64(info.Mode()),
			ModTime: info.ModTime(),
		}
		if err := tw.WriteHeader(header); err != nil {
			return err
		}

		file, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("opening %s: %w", path, err)
		}
		_, copyErr := io.Copy(tw, file)
		_ = file.Close()
		return copyErr
	})
}

// HashDir computes a SHA256 hash of all files in a directory.
func HashDir(dir string) (string, error) {
	return hashDir(dir)
}

func hashDir(dir string) (string, error) {
	var files []string
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		if info.Name() == "Cagefile" && filepath.Dir(path) == dir {
			return nil
		}
		linfo, lstatErr := os.Lstat(path)
		if lstatErr != nil {
			return fmt.Errorf("stat %s: %w", path, lstatErr)
		}
		if linfo.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("symlinks not allowed in agent directory: %s", path)
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		files = append(files, rel)
		return nil
	})
	if err != nil {
		return "", err
	}

	sort.Strings(files)

	h := sha256.New()
	for _, rel := range files {
		// Normalize path separators so the hash is identical across platforms
		h.Write([]byte(filepath.ToSlash(rel)))
		data, err := os.ReadFile(filepath.Join(dir, rel))
		if err != nil {
			return "", err
		}
		h.Write(data)
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}

func validateEntrypointExists(dir, entrypoint string) error {
	parts := strings.Fields(entrypoint)
	if len(parts) < 2 {
		return nil
	}
	script := parts[1]
	path := filepath.Join(dir, script)
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return fmt.Errorf("entrypoint script %q not found in %s", script, dir)
	}
	return nil
}
