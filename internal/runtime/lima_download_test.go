package runtime

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/okedeji/mcpvessel/internal/env"
)

func TestLimaPin_ReadsEmbeddedFile(t *testing.T) {
	v, ok := limaPin("LIMA_VERSION")
	if !ok || v == "" {
		t.Fatalf("LIMA_VERSION not readable from embedded pins: %q", v)
	}
	if _, ok := limaPin("LIMA_SHA256_Darwin_arm64"); !ok {
		t.Error("Darwin_arm64 SHA missing from embedded pins")
	}
	if _, ok := limaPin("NOT_A_KEY"); ok {
		t.Error("limaPin returned ok for a missing key")
	}
}

func TestLimaAsset_TarballAndShaPerPlatform(t *testing.T) {
	version, _ := limaPin("LIMA_VERSION")
	cases := []struct {
		goos, goarch, wantTarball string
	}{
		{"darwin", "arm64", "lima-" + version + "-Darwin-arm64.tar.gz"},
		// x86_64 keeps its underscore; only the OS/arch boundary hyphenates.
		{"darwin", "amd64", "lima-" + version + "-Darwin-x86_64.tar.gz"},
		{"linux", "arm64", "lima-" + version + "-Linux-aarch64.tar.gz"},
		{"linux", "amd64", "lima-" + version + "-Linux-x86_64.tar.gz"},
	}
	for _, c := range cases {
		tb, sha, err := limaAsset(c.goos, c.goarch)
		if err != nil {
			t.Errorf("limaAsset(%s/%s): %v", c.goos, c.goarch, err)
			continue
		}
		if tb != c.wantTarball {
			t.Errorf("limaAsset(%s/%s) tarball = %q, want %q", c.goos, c.goarch, tb, c.wantTarball)
		}
		if len(sha) != 64 {
			t.Errorf("limaAsset(%s/%s) sha = %q, want a 64-char hex", c.goos, c.goarch, sha)
		}
	}
	if _, _, err := limaAsset("plan9", "arm64"); err == nil {
		t.Error("limaAsset should error on an unpinned platform")
	}
}

func TestVerifySHA256_MismatchFailsClosed(t *testing.T) {
	f := filepath.Join(t.TempDir(), "blob")
	if err := os.WriteFile(f, []byte("hello"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	// sha256("hello") is well-known; a wrong pin must be rejected.
	if err := verifySHA256(f, "0000000000000000000000000000000000000000000000000000000000000000"); err == nil {
		t.Fatal("verifySHA256 must reject a mismatched digest")
	}
	const helloSHA = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
	if err := verifySHA256(f, helloSHA); err != nil {
		t.Errorf("verifySHA256 rejected the correct digest: %v", err)
	}
}

// fakeLimaTarball builds a gzip tarball with bin/limactl inside, mirroring the
// real Lima layout, and returns its bytes and sha256.
func fakeLimaTarball(t *testing.T) (data []byte, sha string) {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	body := []byte("#!/bin/sh\necho limactl\n")
	if err := tw.WriteHeader(&tar.Header{Name: "bin/limactl", Mode: 0o755, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
		t.Fatalf("tar header: %v", err)
	}
	if _, err := tw.Write(body); err != nil {
		t.Fatalf("tar write: %v", err)
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar close: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("gz close: %v", err)
	}
	sum := sha256.Sum256(buf.Bytes())
	return buf.Bytes(), hex.EncodeToString(sum[:])
}

// installLima downloads, verifies, extracts, and atomically installs. Drive
// the whole pipeline against a local server so it is hermetic and fast.
func TestInstallLima_FullPipeline(t *testing.T) {
	data, sha := fakeLimaTarball(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(data)
	}))
	defer srv.Close()

	dest := filepath.Join(t.TempDir(), "lima")
	if err := installLima(context.Background(), srv.URL+"/lima.tar.gz", sha, dest); err != nil {
		t.Fatalf("installLima: %v", err)
	}
	limactl := filepath.Join(dest, "bin", "limactl")
	if !isExecutable(limactl) {
		t.Fatalf("limactl not installed executable at %s", limactl)
	}
}

// A byte-for-byte-wrong archive (tampered mirror) must be rejected before
// extraction, and nothing must land in dest.
func TestInstallLima_TamperedArchiveRejected(t *testing.T) {
	data, sha := fakeLimaTarball(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(append(data, 'x')) // one extra byte breaks the digest
	}))
	defer srv.Close()

	dest := filepath.Join(t.TempDir(), "lima")
	err := installLima(context.Background(), srv.URL+"/lima.tar.gz", sha, dest)
	if err == nil {
		t.Fatal("installLima must reject a tampered archive")
	}
	if _, statErr := os.Stat(dest); statErr == nil {
		t.Error("a rejected download must not create dest")
	}
}

// EnsureLimaAvailable must be a pure no-op (never a download) when a usable
// limactl already exists. Plant a fake one at the ~/.mcpvessel/lima path
// FindLimactl searches, so the test is deterministic and never touches the
// network on any platform.
func TestEnsureLimaAvailable_NoopWhenLimactlPresent(t *testing.T) {
	home := t.TempDir()
	t.Setenv(env.Home, home)

	limactl := filepath.Join(home, "lima", "bin", "limactl")
	if err := os.MkdirAll(filepath.Dir(limactl), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(limactl, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatalf("write fake limactl: %v", err)
	}
	if _, err := FindLimactl(); err != nil {
		t.Fatalf("FindLimactl should locate the planted limactl: %v", err)
	}

	// A real download would replace ~/.mcpvessel/lima; assert our fake survives.
	before, _ := os.ReadFile(limactl)
	if err := EnsureLimaAvailable(context.Background(), nil); err != nil {
		t.Fatalf("EnsureLimaAvailable should no-op when limactl exists: %v", err)
	}
	after, err := os.ReadFile(limactl)
	if err != nil || string(before) != string(after) {
		t.Error("EnsureLimaAvailable re-fetched despite a usable limactl")
	}
}
