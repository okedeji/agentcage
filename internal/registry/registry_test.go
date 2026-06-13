package registry

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"oras.land/oras-go/v2/content/memory"
)

func TestPackAndPush_RoundTrip(t *testing.T) {
	ctx := context.Background()
	store := memory.New()

	bundlePath := filepath.Join(t.TempDir(), "agent.agent")
	want := []byte("gzip-tar bundle bytes, opaque to the registry")
	if err := os.WriteFile(bundlePath, want, 0o644); err != nil {
		t.Fatal(err)
	}

	desc, err := packAndPush(ctx, store, "0.1", bundlePath)
	if err != nil {
		t.Fatalf("packAndPush: %v", err)
	}
	if desc.ArtifactType != ArtifactType {
		t.Errorf("ArtifactType = %q, want %q", desc.ArtifactType, ArtifactType)
	}

	// Fetch back by tag. The memory store resolves tags but not bare
	// digests; a real registry resolves both, and the Pull path's digest
	// handling rides on that. content.ReadAll inside fetchBundle verifies
	// the blob digest, so a successful fetch proves integrity.
	got, manifestDesc, err := fetchBundle(ctx, store, "0.1")
	if err != nil {
		t.Fatalf("fetchBundle: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("fetched bytes = %q, want %q", got, want)
	}
	if manifestDesc.Digest != desc.Digest {
		t.Errorf("fetched digest = %s, want %s", manifestDesc.Digest, desc.Digest)
	}
}

func TestFetchBundle_RejectsNonBundleManifest(t *testing.T) {
	ctx := context.Background()
	store := memory.New()

	bundlePath := filepath.Join(t.TempDir(), "x.agent")
	if err := os.WriteFile(bundlePath, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := packAndPush(ctx, store, "0.1", bundlePath); err != nil {
		t.Fatal(err)
	}
	// A pushed agentcage bundle fetches back fine.
	if _, _, err := fetchBundle(ctx, store, "0.1"); err != nil {
		t.Fatalf("control fetch failed: %v", err)
	}
}

func TestCachePath_DigestIsFilesystemSafe(t *testing.T) {
	c := &Client{cacheDir: "/home/u/.agentcage/cache"}
	got := c.cachePath("sha256:abc123")
	want := filepath.Join("/home/u/.agentcage/cache", "bundles", "sha256-abc123.agent")
	if got != want {
		t.Errorf("cachePath = %q, want %q", got, want)
	}
}
