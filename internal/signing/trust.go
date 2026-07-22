package signing

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/okedeji/mcpvessel/internal/env"
)

const trustFileName = "trust.json"

// Pin is one trusted publisher key: pinned on first verified pull and
// required to match on every pull after.
type Pin struct {
	PublicKey string    `json:"public_key"`
	PinnedAt  time.Time `json:"pinned_at"`
}

// TrustStore maps a publisher scope (registry host plus owner, e.g.
// ghcr.io/okedeji) to its pinned signing key. SSH known_hosts semantics: the
// first key seen for a scope is trusted, a different key later fails closed.
type TrustStore struct {
	pins map[string]Pin
}

// Scope is the pinning granularity: the registry host plus the repository's
// first path segment, the namespace one publisher controls.
func Scope(registryHost, repository string) string {
	owner, _, _ := strings.Cut(repository, "/")
	return registryHost + "/" + owner
}

// LoadTrust reads the trust store. A missing file is an empty store; a
// malformed file fails closed rather than silently dropping every pin.
func LoadTrust() (*TrustStore, error) {
	path, err := trustPath()
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return &TrustStore{pins: map[string]Pin{}}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading trust store: %w", err)
	}
	pins := map[string]Pin{}
	if err := json.Unmarshal(raw, &pins); err != nil {
		return nil, fmt.Errorf("parsing trust store %s: %w", path, err)
	}
	return &TrustStore{pins: pins}, nil
}

// Save writes the trust store back with 0600 permissions.
func (t *TrustStore) Save() error {
	path, err := trustPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("creating %s: %w", filepath.Dir(path), err)
	}
	raw, err := json.MarshalIndent(t.pins, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding trust store: %w", err)
	}
	// Write-then-rename so an interrupted write never leaves a truncated
	// trust.json that would fail every future pull closed (a self-DoS).
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return fmt.Errorf("writing trust store: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("finalizing trust store: %w", err)
	}
	return nil
}

// Get returns the pin for scope and whether one exists.
func (t *TrustStore) Get(scope string) (Pin, bool) {
	p, ok := t.pins[scope]
	return p, ok
}

// Scopes returns the pinned scopes, sorted.
func (t *TrustStore) Scopes() []string {
	scopes := make([]string, 0, len(t.pins))
	for s := range t.pins {
		scopes = append(scopes, s)
	}
	sort.Strings(scopes)
	return scopes
}

// Remove deletes a pin, reporting whether it was present.
func (t *TrustStore) Remove(scope string) bool {
	if _, ok := t.pins[scope]; !ok {
		return false
	}
	delete(t.pins, scope)
	return true
}

// pin records a key for scope.
func (t *TrustStore) pin(scope, pubB64 string) {
	if t.pins == nil {
		t.pins = map[string]Pin{}
	}
	t.pins[scope] = Pin{PublicKey: pubB64, PinnedAt: time.Now().UTC()}
}

// VerifyPull is the pull-time policy: verify the signature artifact against
// the pulled digest and repository, then hold the signer's key to the scope's
// pin. First use pins; a mismatch fails closed with the remedy. notify, when
// non-nil, receives human-readable notices (a new pin, a verified pull).
func VerifyPull(sigArtifact []byte, digest, registryHost, repository, requestedTag string, notify func(format string, args ...any)) error {
	pub, err := Verify(sigArtifact, digest, registryHost+"/"+repository, requestedTag)
	if err != nil {
		return err
	}
	scope := Scope(registryHost, repository)
	trust, err := LoadTrust()
	if err != nil {
		return err
	}
	existing, ok := trust.Get(scope)
	switch {
	case !ok:
		trust.pin(scope, pub)
		if err := trust.Save(); err != nil {
			return err
		}
		if notify != nil {
			notify("Signature verified; pinned signing key %s for %s (first use)", Fingerprint(pub), scope)
		}
	case existing.PublicKey == pub:
		if notify != nil {
			notify("Signature verified (key %s)", Fingerprint(pub))
		}
	default:
		return fmt.Errorf(
			"SIGNING KEY MISMATCH for %s: bundle is signed by key %s but key %s was pinned %s.\n"+
				"The publisher may have rotated keys, or this artifact is not from them.\n"+
				"If you have verified the new key out of band, run 'mcpvessel trust rm %s' and pull again",
			scope, Fingerprint(pub), Fingerprint(existing.PublicKey),
			existing.PinnedAt.Format("2006-01-02"), scope)
	}
	return nil
}

func trustPath() (string, error) {
	home, err := env.HomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, trustFileName), nil
}
