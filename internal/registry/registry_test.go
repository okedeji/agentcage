package registry

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	oras "oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/content/memory"

	"github.com/okedeji/mcpvessel/internal/bundle"
	"github.com/okedeji/mcpvessel/internal/reference"
	"github.com/okedeji/mcpvessel/internal/signing"
)

// realBundle builds a minimal valid .agent; packBundle needs a readable
// manifest to pin the created annotation to built_at.
func realBundle(t *testing.T) string {
	t.Helper()
	src := t.TempDir()
	if err := os.WriteFile(filepath.Join(src, "Vesselfile"), []byte("FROM x\nENTRYPOINT y\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "agent.agent")
	if err := bundle.Build(src, out); err != nil {
		t.Fatalf("Build: %v", err)
	}
	return out
}

func TestPackBundle_RoundTrip(t *testing.T) {
	ctx := context.Background()
	store := memory.New()
	bundlePath := realBundle(t)
	want, err := os.ReadFile(bundlePath)
	if err != nil {
		t.Fatal(err)
	}

	desc, err := packBundle(ctx, store, "0.1", bundlePath, nil)
	if err != nil {
		t.Fatalf("packBundle: %v", err)
	}
	if desc.ArtifactType != ArtifactType {
		t.Errorf("ArtifactType = %q, want %q", desc.ArtifactType, ArtifactType)
	}

	got, manifestDesc, err := fetchBundle(ctx, store, "0.1")
	if err != nil {
		t.Fatalf("fetchBundle: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("fetched bytes differ from the pushed bundle")
	}
	if manifestDesc.Digest != desc.Digest {
		t.Errorf("fetched digest = %s, want %s", manifestDesc.Digest, desc.Digest)
	}
}

func TestBundleDigest_DeterministicAndMatchesPush(t *testing.T) {
	bundlePath := realBundle(t)

	d1, err := BundleDigest(bundlePath)
	if err != nil {
		t.Fatalf("BundleDigest: %v", err)
	}
	d2, err := BundleDigest(bundlePath)
	if err != nil {
		t.Fatalf("BundleDigest (again): %v", err)
	}
	if d1 != d2 {
		t.Errorf("BundleDigest is not deterministic: %s vs %s", d1, d2)
	}

	// A locally locked USES digest must stay valid once the dependency is pushed.
	desc, err := packBundle(context.Background(), memory.New(), "0.1", bundlePath, nil)
	if err != nil {
		t.Fatalf("packBundle: %v", err)
	}
	if d1 != desc.Digest.String() {
		t.Errorf("BundleDigest %s != push digest %s", d1, desc.Digest.String())
	}
}

func TestPackBundle_StampsOwnershipForPublish(t *testing.T) {
	ctx := context.Background()
	store := memory.New()
	name := "io.github.me/x"

	desc, err := packBundle(ctx, store, "0.1", realBundle(t), map[string]string{mcpServerNameAnnotation: name})
	if err != nil {
		t.Fatalf("packBundle: %v", err)
	}

	mb, err := content.FetchAll(ctx, store, desc)
	if err != nil {
		t.Fatal(err)
	}
	var man ocispec.Manifest
	if err := json.Unmarshal(mb, &man); err != nil {
		t.Fatal(err)
	}
	if man.Annotations[mcpServerNameAnnotation] != name {
		t.Errorf("manifest annotation = %q, want %q", man.Annotations[mcpServerNameAnnotation], name)
	}

	// The MCP Registry reads the marker from the config's Labels, not only the
	// manifest annotation.
	cb, err := content.FetchAll(ctx, store, man.Config)
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		Config struct {
			Labels map[string]string `json:"Labels"`
		} `json:"config"`
	}
	if err := json.Unmarshal(cb, &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.Config.Labels[mcpServerNameAnnotation] != name {
		t.Errorf("config label = %q, want %q", cfg.Config.Labels[mcpServerNameAnnotation], name)
	}
}

func TestSeedCache_MakesPullALocalHit(t *testing.T) {
	ctx := context.Background()
	home := t.TempDir()
	t.Setenv("VESSEL_HOME", home)

	bundlePath := realBundle(t)
	digest, err := BundleDigest(bundlePath)
	if err != nil {
		t.Fatalf("BundleDigest: %v", err)
	}

	if err := SeedCache(digest, bundlePath); err != nil {
		t.Fatalf("SeedCache: %v", err)
	}
	c := &Client{cacheDir: filepath.Join(home, "cache")}

	// A digest-pinned Pull must short-circuit from the cache with no network.
	ref, err := reference.Parse("ghcr.io/x/y@" + digest)
	if err != nil {
		t.Fatal(err)
	}
	path, gotDigest, err := c.Pull(ctx, ref)
	if err != nil {
		t.Fatalf("Pull after seed: %v", err)
	}
	if gotDigest != digest {
		t.Errorf("pulled digest = %s, want %s", gotDigest, digest)
	}
	if path != c.cachePath(digest) {
		t.Errorf("pulled path = %s, want the cache path", path)
	}
}

func TestSeedCache_DoesNotMarkVerified(t *testing.T) {
	home := t.TempDir()
	t.Setenv("VESSEL_HOME", home)

	bundlePath := realBundle(t)
	digest, err := BundleDigest(bundlePath)
	if err != nil {
		t.Fatalf("BundleDigest: %v", err)
	}
	if err := SeedCache(digest, bundlePath); err != nil {
		t.Fatalf("SeedCache: %v", err)
	}

	// Locally seeded bytes are not registry-verified, so strict-mode digest
	// pulls must not treat them as verified.
	c := &Client{cacheDir: filepath.Join(home, "cache")}
	if c.isVerified("ghcr.io/okedeji", digest) {
		t.Error("seeded cache entry must not carry a verified marker")
	}
}

func TestMarkVerified_RoundTrip(t *testing.T) {
	c := &Client{cacheDir: t.TempDir()}
	const scope, digest = "ghcr.io/okedeji", "sha256:abc123"
	if c.isVerified(scope, digest) {
		t.Fatal("marker should be absent before markVerified")
	}
	if err := c.markVerified(scope, digest); err != nil {
		t.Fatalf("markVerified: %v", err)
	}
	if !c.isVerified(scope, digest) {
		t.Error("marker should be present after markVerified")
	}
}

func TestMarkVerified_IsScopeKeyed(t *testing.T) {
	// The same immutable digest can live in two repos under two publisher scopes.
	// A marker earned under one scope must not satisfy the other, so a strict-mode
	// digest pull under the second scope still runs its own pinned-key check.
	c := &Client{cacheDir: t.TempDir()}
	const digest = "sha256:abc123"
	if err := c.markVerified("ghcr.io/alice", digest); err != nil {
		t.Fatalf("markVerified: %v", err)
	}
	if !c.isVerified("ghcr.io/alice", digest) {
		t.Error("marker absent for the scope that earned it")
	}
	if c.isVerified("ghcr.io/eve", digest) {
		t.Error("marker leaked across publisher scopes: eve inherited alice's verification")
	}
}

func TestEnforceCachedDigestPolicy_NonStrictIsNoOp(t *testing.T) {
	// No VESSEL_REQUIRE_SIGNATURES: an unverified digest cache hit is served
	// with no network access.
	c := &Client{cacheDir: t.TempDir()}
	ref := mustParseRef(t, "@okedeji/researcher:0.1")
	if err := c.enforceCachedDigestPolicy(context.Background(), ref, "sha256:abc"); err != nil {
		t.Fatalf("non-strict cache hit should be a no-op, got %v", err)
	}
}

func TestEnforceCachedDigestPolicy_StrictWithMarkerSkipsNetwork(t *testing.T) {
	t.Setenv("VESSEL_HOME", t.TempDir())
	t.Setenv("VESSEL_REQUIRE_SIGNATURES", "1")

	c := &Client{cacheDir: t.TempDir()}
	const digest = "sha256:abc123"
	// Mark under the scope this ref resolves to, so the strict-mode enforce finds
	// its own scope's marker.
	ref := mustParseRef(t, "@okedeji/researcher:0.1")
	if err := c.markVerified(signing.Scope(ref.Registry, ref.Repository), digest); err != nil {
		t.Fatalf("markVerified: %v", err)
	}
	// A present marker satisfies strict mode without touching the network; an
	// unreachable/undefined registry would error if it tried.
	if err := c.enforceCachedDigestPolicy(context.Background(), ref, digest); err != nil {
		t.Fatalf("verified marker should satisfy strict mode offline, got %v", err)
	}
}

func TestFetchBundle_RejectsNonBundleManifest(t *testing.T) {
	ctx := context.Background()
	store := memory.New()

	// The only layer has a foreign media type: some other OCI artifact.
	blob := content.NewDescriptorFromBytes("application/octet-stream", []byte("not a bundle"))
	if err := store.Push(ctx, blob, bytes.NewReader([]byte("not a bundle"))); err != nil {
		t.Fatal(err)
	}
	desc, err := oras.PackManifest(ctx, store, oras.PackManifestVersion1_1, "application/vnd.example", oras.PackManifestOptions{
		Layers: []ocispec.Descriptor{blob},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Tag(ctx, desc, "0.1"); err != nil {
		t.Fatal(err)
	}

	if _, _, err := fetchBundle(ctx, store, "0.1"); err == nil || !bytes.Contains([]byte(err.Error()), []byte("not an mcpvessel bundle")) {
		t.Fatalf("err = %v, want a not-an-mcpvessel-bundle rejection", err)
	}
}

func TestCachePath_DigestIsFilesystemSafe(t *testing.T) {
	c := &Client{cacheDir: "/home/u/.mcpvessel/cache"}
	got := c.cachePath("sha256:abc123")
	want := filepath.Join("/home/u/.mcpvessel/cache", "bundles", "sha256-abc123.agent")
	if got != want {
		t.Errorf("cachePath = %q, want %q", got, want)
	}
}
