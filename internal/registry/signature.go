package registry

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	oras "oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/errdef"

	"github.com/okedeji/mcpvessel/internal/config"
	"github.com/okedeji/mcpvessel/internal/env"
	"github.com/okedeji/mcpvessel/internal/reference"
	"github.com/okedeji/mcpvessel/internal/signing"
)

const (
	// SignatureMediaType is the OCI layer media type for a bundle signature.
	SignatureMediaType = "application/vnd.mcpvessel.signature.v1+json"

	// SignatureArtifactType marks a signature's OCI manifest.
	SignatureArtifactType = "application/vnd.mcpvessel.signature.v1"
)

// signatureTag maps a bundle's manifest digest to the tag its signature lives
// under, the cosign convention: sha256:abc becomes sha256-abc.sig. Any OCI
// registry can hold it; no referrers API needed.
func signatureTag(digest string) string {
	return strings.ReplaceAll(digest, ":", "-") + ".sig"
}

// PushSignature uploads a signature artifact next to the bundle it signs.
func (c *Client) PushSignature(ctx context.Context, ref reference.Reference, digest string, sig []byte) error {
	repo, err := c.repository(ref)
	if err != nil {
		return err
	}
	if err := pushSignature(ctx, repo, digest, sig); err != nil {
		return fmt.Errorf("pushing signature for %s: %w", ref.OCIRef(), err)
	}
	return nil
}

// pushSignature uploads the signature blob, packs its manifest, and tags it
// under the signed digest's signature tag.
func pushSignature(ctx context.Context, dst oras.Target, digest string, sig []byte) error {
	blob := content.NewDescriptorFromBytes(SignatureMediaType, sig)
	exists, err := dst.Exists(ctx, blob)
	if err != nil {
		return fmt.Errorf("checking signature blob: %w", err)
	}
	if !exists {
		if err := dst.Push(ctx, blob, bytes.NewReader(sig)); err != nil {
			return fmt.Errorf("uploading signature blob: %w", err)
		}
	}
	manifestDesc, err := oras.PackManifest(ctx, dst, oras.PackManifestVersion1_1, SignatureArtifactType, oras.PackManifestOptions{
		Layers: []ocispec.Descriptor{blob},
	})
	if err != nil {
		return fmt.Errorf("packing signature manifest: %w", err)
	}
	if err := dst.Tag(ctx, manifestDesc, signatureTag(digest)); err != nil {
		return fmt.Errorf("tagging signature: %w", err)
	}
	return nil
}

// fetchSignature returns the signature artifact for digest, or ok false when
// none is published. Any error other than absence is reported: a registry
// that cannot answer is not the same as an unsigned bundle.
func fetchSignature(ctx context.Context, src oras.ReadOnlyTarget, digest string) (sig []byte, ok bool, err error) {
	desc, err := src.Resolve(ctx, signatureTag(digest))
	if errors.Is(err, errdef.ErrNotFound) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("resolving signature: %w", err)
	}
	mrc, err := src.Fetch(ctx, desc)
	if err != nil {
		return nil, false, fmt.Errorf("fetching signature manifest: %w", err)
	}
	manifestBytes, err := content.ReadAll(mrc, desc)
	_ = mrc.Close()
	if err != nil {
		return nil, false, fmt.Errorf("reading signature manifest: %w", err)
	}
	var manifest ocispec.Manifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		return nil, false, fmt.Errorf("decoding signature manifest: %w", err)
	}
	var layer ocispec.Descriptor
	found := false
	for _, l := range manifest.Layers {
		if l.MediaType == SignatureMediaType {
			layer, found = l, true
			break
		}
	}
	if !found {
		return nil, false, fmt.Errorf("signature manifest has no %s layer", SignatureMediaType)
	}
	brc, err := src.Fetch(ctx, layer)
	if err != nil {
		return nil, false, fmt.Errorf("fetching signature blob: %w", err)
	}
	data, err := content.ReadAll(brc, layer)
	_ = brc.Close()
	if err != nil {
		return nil, false, fmt.Errorf("reading signature blob: %w", err)
	}
	return data, true, nil
}

// verifyPulled enforces the signature policy at cache ingest, the one point
// every network pull passes. A published signature must verify and match the
// scope's pinned key. An unsigned bundle passes unless
// VESSEL_REQUIRE_SIGNATURES is set, in which case it fails closed.
func (c *Client) verifyPulled(ctx context.Context, src oras.ReadOnlyTarget, ref reference.Reference, digest string) error {
	sig, ok, err := fetchSignature(ctx, src, digest)
	if err != nil {
		return fmt.Errorf("checking signature for %s: %w", ref.OCIRef(), err)
	}
	if !ok {
		if requireSignatures() {
			return fmt.Errorf("%s is not signed and %s is set; unset it or ask the publisher for a signed push", ref.OCIRef(), env.RequireSignatures)
		}
		c.notify("Signature: none (unsigned bundle)")
		return nil
	}
	return signing.VerifyPull(sig, digest, ref.Registry, ref.Repository, c.notify)
}

// notify forwards a human-readable notice to the client's Notify hook when
// one is set. Enforcement never depends on it.
func (c *Client) notify(format string, args ...any) {
	if c.Notify != nil {
		c.Notify(format, args...)
	}
}

// requireSignatures reads the strict-mode knob: any value other than empty,
// "0", or "false" requires every pulled bundle to be signed.
func requireSignatures() bool {
	v := strings.ToLower(strings.TrimSpace(config.LookupEnv(env.RequireSignatures)))
	return v != "" && v != "0" && v != "false"
}
