package runtime

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/okedeji/agentcage/internal/env"
)

// limaReleasePins is the single source of truth for the bundled Lima version
// and per-platform tarball SHA-256s. The Makefile reads the same file so a
// release build and a runtime auto-fetch pin the identical bytes. Bumping Lima
// means editing this file and nothing else.
//
//go:embed lima_release.txt
var limaReleasePins string

const limaDownloadTimeout = 5 * time.Minute

// limaPin returns a value from the pins file by key.
func limaPin(key string) (string, bool) {
	for _, line := range strings.Split(limaReleasePins, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == key {
			return fields[1], true
		}
	}
	return "", false
}

// limaAsset resolves the release tarball name and its pinned SHA-256 for a
// GOOS/GOARCH. The SHA pin key uses Lima's underscore platform names
// (Darwin_x86_64), while the tarball filename hyphenates only the OS/arch
// boundary and keeps x86_64 intact (lima-<ver>-Darwin-x86_64.tar.gz), so the
// two are mapped explicitly rather than by substitution.
func limaAsset(goos, goarch string) (tarball, sha256Hex string, err error) {
	var shaKey, suffix string
	switch goos + "/" + goarch {
	case "darwin/arm64":
		shaKey, suffix = "Darwin_arm64", "Darwin-arm64"
	case "darwin/amd64":
		shaKey, suffix = "Darwin_x86_64", "Darwin-x86_64"
	case "linux/arm64":
		shaKey, suffix = "Linux_aarch64", "Linux-aarch64"
	case "linux/amd64":
		shaKey, suffix = "Linux_x86_64", "Linux-x86_64"
	default:
		return "", "", fmt.Errorf("no pinned Lima build for %s/%s", goos, goarch)
	}
	version, ok := limaPin("LIMA_VERSION")
	if !ok {
		return "", "", fmt.Errorf("lima pins: LIMA_VERSION missing")
	}
	sha, ok := limaPin("LIMA_SHA256_" + shaKey)
	if !ok {
		return "", "", fmt.Errorf("lima pins: SHA for %s missing", shaKey)
	}
	return fmt.Sprintf("lima-%s-%s.tar.gz", version, suffix), sha, nil
}

// EnsureLimaAvailable makes sure a usable limactl exists, downloading the
// pinned Lima bundle into ~/.agentcage/lima on first use if none is found. It
// is a no-op off macOS (Linux runs agents on host containerd, no VM) and a
// no-op when limactl is already bundled next to the binary or on PATH. The
// download is SHA-256 verified against the pin before anything is extracted,
// so a tampered mirror cannot install a different binary.
func EnsureLimaAvailable(ctx context.Context, w io.Writer) error {
	if runtime.GOOS != "darwin" {
		return nil
	}
	if _, err := FindLimactl(); err == nil {
		return nil
	}

	tarball, wantSHA, err := limaAsset(runtime.GOOS, runtime.GOARCH)
	if err != nil {
		return err
	}
	version, _ := limaPin("LIMA_VERSION")

	home, err := env.HomeDir()
	if err != nil {
		return err
	}
	dest := filepath.Join(home, "lima")
	url := fmt.Sprintf("%s/v%s/%s", limaBaseURL, version, tarball)

	if w != nil {
		_, _ = fmt.Fprintf(w, "Downloading Lima v%s (one-time, ~80MB)...\n", version)
	}
	if err := installLima(ctx, url, wantSHA, dest); err != nil {
		return err
	}
	if _, err := FindLimactl(); err != nil {
		return fmt.Errorf("lima installed to %s but limactl still not found: %w", dest, err)
	}
	if w != nil {
		_, _ = fmt.Fprintf(w, "Installed Lima v%s to %s\n", version, dest)
	}
	return nil
}

// limaBaseURL is the release download root, a var so a test can point it at a
// local server instead of the network.
var limaBaseURL = "https://github.com/lima-vm/lima/releases/download"

// installLima downloads url, verifies it against wantSHA, extracts it, and
// swaps it into dest atomically. Verification happens before extraction, so a
// tampered archive is never unpacked. The rename makes the install all-or-
// nothing: a crash mid-way never leaves a half-written dest.
func installLima(ctx context.Context, url, wantSHA, dest string) error {
	ctx, cancel := context.WithTimeout(ctx, limaDownloadTimeout)
	defer cancel()

	tmpDir, err := os.MkdirTemp(filepath.Dir(dest), "lima-dl-")
	if err != nil {
		return fmt.Errorf("creating lima download dir: %w", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	archive := filepath.Join(tmpDir, "lima.tar.gz")
	if err := downloadFile(ctx, url, archive); err != nil {
		return fmt.Errorf("downloading Lima: %w", err)
	}
	if err := verifySHA256(archive, wantSHA); err != nil {
		return err
	}

	extractDir := filepath.Join(tmpDir, "extract")
	if err := os.MkdirAll(extractDir, 0o755); err != nil {
		return err
	}
	if err := extractTarGz(ctx, archive, extractDir); err != nil {
		return fmt.Errorf("extracting Lima: %w", err)
	}
	limactl := filepath.Join(extractDir, "bin", "limactl")
	if !isExecutable(limactl) {
		if err := os.Chmod(limactl, 0o755); err != nil {
			return fmt.Errorf("lima archive missing an executable bin/limactl: %w", err)
		}
	}

	// Same filesystem (both under ~/.agentcage), so rename is atomic.
	_ = os.RemoveAll(dest)
	if err := os.Rename(extractDir, dest); err != nil {
		return fmt.Errorf("installing Lima to %s: %w", dest, err)
	}
	return nil
}

func downloadFile(ctx context.Context, url, dest string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: HTTP %d", url, resp.StatusCode)
	}
	f, err := os.Create(dest)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, resp.Body); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// verifySHA256 fails closed unless the file's digest matches wantHex exactly.
func verifySHA256(path, wantHex string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return err
	}
	got := hex.EncodeToString(h.Sum(nil))
	if got != wantHex {
		return fmt.Errorf("lima download sha256 mismatch: got %s, want %s (tampered mirror or wrong pin)", got, wantHex)
	}
	return nil
}

// extractTarGz unpacks a gzip tarball via the system tar. The archive is
// already SHA-verified against the pin before this runs, so its contents are
// the exact known-good Lima release, not attacker-controlled.
func extractTarGz(ctx context.Context, tarball, destDir string) error {
	cmd := exec.CommandContext(ctx, "tar", "-xzf", tarball, "-C", destDir)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("tar: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}
