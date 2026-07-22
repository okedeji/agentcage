// Package signing signs pushed bundles and verifies pulled ones. A signature
// is ed25519 over the bundle's OCI manifest digest plus the repository it was
// pushed to, so a valid signature cannot be replayed onto other bytes or
// another publisher's name. Verification pins a publisher's key on first use
// (trust.go); integrity of the bytes themselves is the digest's job.
package signing

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/okedeji/mcpvessel/internal/env"
)

// ArtifactVersion is the locked signature artifact schema version. Bumped to
// 0.2 when the signed payload gained the tag, so a pre-0.2 signature (which
// binds no version and would let a downgrade substitution pass) is rejected
// with a clear "re-push" error rather than silently accepted.
const ArtifactVersion = "0.2"

const keyFileName = "signing-key.json"

// Key is this host's bundle signing keypair.
type Key struct {
	Private ed25519.PrivateKey
	Public  ed25519.PublicKey
}

// keyFile is the on-disk form. The seed alone reconstructs the keypair.
type keyFile struct {
	Version   string    `json:"version"`
	Algorithm string    `json:"algorithm"`
	Seed      string    `json:"seed"`
	PublicKey string    `json:"public_key"`
	CreatedAt time.Time `json:"created_at"`
}

// KeyPath resolves ~/.mcpvessel/signing-key.json, honoring VESSEL_HOME.
func KeyPath() (string, error) {
	home, err := env.HomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, keyFileName), nil
}

// LoadKey reads the signing key. ok is false when none exists yet; a
// malformed or inconsistent key file fails closed.
func LoadKey() (*Key, bool, error) {
	path, err := KeyPath()
	if err != nil {
		return nil, false, err
	}
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("reading signing key: %w", err)
	}
	key, err := parseKey(raw, path)
	if err != nil {
		return nil, false, err
	}
	return key, true, nil
}

// parseKey validates raw key-file bytes; label names the source in errors.
func parseKey(raw []byte, label string) (*Key, error) {
	var f keyFile
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("parsing signing key %s: %w", label, err)
	}
	if f.Algorithm != "ed25519" {
		return nil, fmt.Errorf("signing key %s: unsupported algorithm %q", label, f.Algorithm)
	}
	seed, err := base64.StdEncoding.DecodeString(f.Seed)
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("signing key %s: malformed seed", label)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	if base64.StdEncoding.EncodeToString(pub) != f.PublicKey {
		return nil, fmt.Errorf("signing key %s: public key does not match seed", label)
	}
	return &Key{Private: priv, Public: pub}, nil
}

// ExportKey returns the key file's bytes after validating them, so a corrupt
// key is caught at export, not at import on the other machine.
func ExportKey() ([]byte, error) {
	if _, ok, err := LoadKey(); err != nil {
		return nil, err
	} else if !ok {
		return nil, fmt.Errorf("no signing key to export; 'mcpvessel keys' or a signed push generates one")
	}
	path, err := KeyPath()
	if err != nil {
		return nil, err
	}
	return os.ReadFile(path)
}

// ImportKey installs an exported key file so several machines (a laptop and
// CI) sign as the same publisher. Importing the key already installed is a
// no-op; a different key is refused unless force, since replacing it changes
// what this host signs as.
func ImportKey(raw []byte, force bool) (*Key, error) {
	key, err := parseKey(raw, "(stdin)")
	if err != nil {
		return nil, err
	}
	existing, ok, err := LoadKey()
	if err != nil {
		return nil, err
	}
	if ok {
		if PublicKeyEncoded(existing.Public) == PublicKeyEncoded(key.Public) {
			return key, nil
		}
		if !force {
			return nil, fmt.Errorf(
				"a different signing key already exists here (%s); pass --force to replace it with %s",
				Fingerprint(PublicKeyEncoded(existing.Public)), Fingerprint(PublicKeyEncoded(key.Public)))
		}
	}
	path, err := KeyPath()
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("creating %s: %w", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		return nil, fmt.Errorf("writing signing key: %w", err)
	}
	return key, nil
}

// EnsureKey loads the signing key, generating and persisting one on first
// use. created reports whether this call generated it.
func EnsureKey() (key *Key, created bool, err error) {
	key, ok, err := LoadKey()
	if err != nil {
		return nil, false, err
	}
	if ok {
		return key, false, nil
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, false, fmt.Errorf("generating signing key: %w", err)
	}
	path, err := KeyPath()
	if err != nil {
		return nil, false, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, false, fmt.Errorf("creating %s: %w", filepath.Dir(path), err)
	}
	raw, err := json.MarshalIndent(keyFile{
		Version:   ArtifactVersion,
		Algorithm: "ed25519",
		Seed:      base64.StdEncoding.EncodeToString(priv.Seed()),
		PublicKey: base64.StdEncoding.EncodeToString(pub),
		CreatedAt: time.Now().UTC(),
	}, "", "  ")
	if err != nil {
		return nil, false, fmt.Errorf("encoding signing key: %w", err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		return nil, false, fmt.Errorf("writing signing key: %w", err)
	}
	return &Key{Private: priv, Public: pub}, true, nil
}

// Fingerprint is the short identifier shown for a public key: the first 12
// hex chars of its sha256. Stable across encodings; safe to publish.
func Fingerprint(pubB64 string) string {
	sum := sha256.Sum256([]byte(pubB64))
	return hex.EncodeToString(sum[:])[:12]
}

// PublicKeyEncoded is the base64 form used everywhere a key is stored,
// compared, or displayed.
func PublicKeyEncoded(pub ed25519.PublicKey) string {
	return base64.StdEncoding.EncodeToString(pub)
}

// payload is what gets signed. Repository is registry host plus repository
// path (ghcr.io/org/name), binding the signature to the publisher's namespace.
type payload struct {
	Digest     string `json:"digest"`
	Repository string `json:"repository"`
	// Tag binds the signature to the version it was published as, so a hostile
	// registry cannot answer a request for :2.0 with an older, genuinely-signed
	// :1.0 digest (a downgrade). A digest-pinned pull carries no tag and does not
	// check this (the digest is the content).
	Tag string `json:"tag,omitempty"`
}

// artifact is the signature file pushed next to a bundle. Payload carries the
// exact signed bytes, so verification never depends on JSON re-serialization
// agreeing with the signer's.
type artifact struct {
	Version   string `json:"version"`
	Payload   string `json:"payload"`
	PublicKey string `json:"public_key"`
	Signature string `json:"signature"`
}

// Sign produces the signature artifact for a pushed bundle. tag is the version
// being published (empty is allowed for a tagless push, but then a later tagged
// pull of the same digest cannot be version-verified).
func Sign(key *Key, digest, repository, tag string) ([]byte, error) {
	if digest == "" || repository == "" {
		return nil, fmt.Errorf("signing needs a digest and repository")
	}
	body, err := json.Marshal(payload{Digest: digest, Repository: repository, Tag: tag})
	if err != nil {
		return nil, fmt.Errorf("encoding signature payload: %w", err)
	}
	sig := ed25519.Sign(key.Private, body)
	return json.MarshalIndent(artifact{
		Version:   ArtifactVersion,
		Payload:   base64.StdEncoding.EncodeToString(body),
		PublicKey: PublicKeyEncoded(key.Public),
		Signature: base64.StdEncoding.EncodeToString(sig),
	}, "", "  ")
}

// Verify checks a signature artifact against the pulled digest and
// repository, returning the signer's base64 public key. It proves the
// signature is valid and bound to these bytes and this name; whether the key
// is the one trusted for the publisher is trust.go's call.
// requestedTag is the tag the caller asked for. When non-empty (a tag pull),
// the signed tag must match it, which is what blocks a downgrade substitution.
// When empty (a digest pull), the tag is not checked: the digest already fixes
// the content.
func Verify(raw []byte, digest, repository, requestedTag string) (pubB64 string, err error) {
	var a artifact
	if err := json.Unmarshal(raw, &a); err != nil {
		return "", fmt.Errorf("parsing signature: %w", err)
	}
	if a.Version != ArtifactVersion {
		return "", fmt.Errorf("signature version %q is not %q", a.Version, ArtifactVersion)
	}
	body, err := base64.StdEncoding.DecodeString(a.Payload)
	if err != nil {
		return "", fmt.Errorf("signature payload is not base64: %w", err)
	}
	pub, err := base64.StdEncoding.DecodeString(a.PublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return "", fmt.Errorf("signature carries a malformed public key")
	}
	sig, err := base64.StdEncoding.DecodeString(a.Signature)
	if err != nil {
		return "", fmt.Errorf("signature is not base64: %w", err)
	}
	if !ed25519.Verify(pub, body, sig) {
		return "", fmt.Errorf("signature does not verify: payload or signature has been altered")
	}
	var p payload
	if err := json.Unmarshal(body, &p); err != nil {
		return "", fmt.Errorf("parsing signed payload: %w", err)
	}
	if p.Digest != digest {
		return "", fmt.Errorf("signature is for digest %s, not %s", p.Digest, digest)
	}
	if !bytes.Equal([]byte(p.Repository), []byte(repository)) {
		return "", fmt.Errorf("signature is for %s, not %s", p.Repository, repository)
	}
	if requestedTag != "" && p.Tag != requestedTag {
		return "", fmt.Errorf("signature is for version %q, not %q: the registry may be substituting an older signed version (downgrade)", p.Tag, requestedTag)
	}
	return a.PublicKey, nil
}
