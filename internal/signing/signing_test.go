package signing

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/okedeji/mcpvessel/internal/env"
)

func setHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv(env.Home, home)
	return home
}

func TestEnsureKey_GeneratesOnceAndReloads(t *testing.T) {
	home := setHome(t)

	k1, created, err := EnsureKey()
	if err != nil {
		t.Fatalf("EnsureKey: %v", err)
	}
	if !created {
		t.Fatal("first EnsureKey should generate")
	}
	info, err := os.Stat(filepath.Join(home, "signing-key.json"))
	if err != nil {
		t.Fatalf("key file: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("key file mode = %o, want 0600", perm)
	}

	k2, created, err := EnsureKey()
	if err != nil {
		t.Fatalf("second EnsureKey: %v", err)
	}
	if created {
		t.Fatal("second EnsureKey must reload, not regenerate")
	}
	if PublicKeyEncoded(k1.Public) != PublicKeyEncoded(k2.Public) {
		t.Error("reloaded key differs from generated key")
	}
}

func TestLoadKey_MissingIsNotAnError(t *testing.T) {
	setHome(t)
	_, ok, err := LoadKey()
	if err != nil {
		t.Fatalf("LoadKey: %v", err)
	}
	if ok {
		t.Fatal("no key exists yet; ok should be false")
	}
}

func TestLoadKey_TamperedSeedFailsClosed(t *testing.T) {
	home := setHome(t)
	if _, _, err := EnsureKey(); err != nil {
		t.Fatalf("EnsureKey: %v", err)
	}
	path := filepath.Join(home, "signing-key.json")
	raw, _ := os.ReadFile(path)
	var f map[string]any
	_ = json.Unmarshal(raw, &f)
	f["public_key"] = base64.StdEncoding.EncodeToString(make([]byte, 32))
	out, _ := json.Marshal(f)
	_ = os.WriteFile(path, out, 0o600)

	_, _, err := LoadKey()
	if err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("err = %v, want a seed/public mismatch rejection", err)
	}
}

func TestSignVerify_RoundTrip(t *testing.T) {
	setHome(t)
	key, _, err := EnsureKey()
	if err != nil {
		t.Fatalf("EnsureKey: %v", err)
	}
	sig, err := Sign(key, "sha256:abc123", "ghcr.io/okedeji/researcher")
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	pub, err := Verify(sig, "sha256:abc123", "ghcr.io/okedeji/researcher")
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if pub != PublicKeyEncoded(key.Public) {
		t.Error("Verify returned a different public key than signed")
	}
}

func TestVerify_WrongDigestOrRepositoryFails(t *testing.T) {
	setHome(t)
	key, _, _ := EnsureKey()
	sig, _ := Sign(key, "sha256:abc123", "ghcr.io/okedeji/researcher")

	if _, err := Verify(sig, "sha256:other", "ghcr.io/okedeji/researcher"); err == nil {
		t.Error("verify with wrong digest must fail")
	}
	if _, err := Verify(sig, "sha256:abc123", "ghcr.io/attacker/researcher"); err == nil {
		t.Error("verify with wrong repository must fail: cross-repo replay")
	}
}

func TestVerify_TamperedPayloadFails(t *testing.T) {
	setHome(t)
	key, _, _ := EnsureKey()
	sig, _ := Sign(key, "sha256:abc123", "ghcr.io/okedeji/researcher")

	var a map[string]string
	_ = json.Unmarshal(sig, &a)
	forged, _ := json.Marshal(map[string]string{"digest": "sha256:evil", "repository": "ghcr.io/okedeji/researcher"})
	a["payload"] = base64.StdEncoding.EncodeToString(forged)
	tampered, _ := json.Marshal(a)

	if _, err := Verify(tampered, "sha256:evil", "ghcr.io/okedeji/researcher"); err == nil {
		t.Fatal("a re-written payload must not verify against the old signature")
	}
}

func TestVerifyPull_TOFUPinsThenHolds(t *testing.T) {
	setHome(t)
	key, _, _ := EnsureKey()
	sig, _ := Sign(key, "sha256:abc", "ghcr.io/okedeji/researcher")

	var notices []string
	notify := func(format string, args ...any) { notices = append(notices, format) }

	// First pull pins.
	if err := VerifyPull(sig, "sha256:abc", "ghcr.io", "okedeji/researcher", notify); err != nil {
		t.Fatalf("first VerifyPull: %v", err)
	}
	trust, _ := LoadTrust()
	if _, ok := trust.Get("ghcr.io/okedeji"); !ok {
		t.Fatal("first verified pull should pin the scope")
	}

	// Same key, different repo in the same scope: passes against the pin.
	sig2, _ := Sign(key, "sha256:def", "ghcr.io/okedeji/other")
	if err := VerifyPull(sig2, "sha256:def", "ghcr.io", "okedeji/other", nil); err != nil {
		t.Fatalf("same-key pull: %v", err)
	}

	if len(notices) == 0 || !strings.Contains(notices[0], "first use") {
		t.Errorf("pin notice missing: %v", notices)
	}
}

func TestVerifyPull_KeyMismatchFailsClosed(t *testing.T) {
	setHome(t)
	key, _, _ := EnsureKey()
	sig, _ := Sign(key, "sha256:abc", "ghcr.io/okedeji/researcher")
	if err := VerifyPull(sig, "sha256:abc", "ghcr.io", "okedeji/researcher", nil); err != nil {
		t.Fatalf("pin: %v", err)
	}

	// A different key signs for the same scope.
	keyPath, _ := KeyPath()
	_ = os.Remove(keyPath)
	attacker, _, _ := EnsureKey()
	forged, _ := Sign(attacker, "sha256:abc", "ghcr.io/okedeji/researcher")

	err := VerifyPull(forged, "sha256:abc", "ghcr.io", "okedeji/researcher", nil)
	if err == nil {
		t.Fatal("a different key for a pinned scope must fail closed")
	}
	if !strings.Contains(err.Error(), "trust rm") {
		t.Errorf("mismatch error should name the remedy, got: %v", err)
	}
}

func TestTrustStore_RemoveAllowsRepin(t *testing.T) {
	setHome(t)
	key, _, _ := EnsureKey()
	sig, _ := Sign(key, "sha256:abc", "ghcr.io/okedeji/researcher")
	_ = VerifyPull(sig, "sha256:abc", "ghcr.io", "okedeji/researcher", nil)

	trust, _ := LoadTrust()
	if !trust.Remove("ghcr.io/okedeji") {
		t.Fatal("Remove should report the pin existed")
	}
	if err := trust.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Re-pin with a new key succeeds after removal.
	keyPath, _ := KeyPath()
	_ = os.Remove(keyPath)
	rotated, _, _ := EnsureKey()
	sig2, _ := Sign(rotated, "sha256:abc", "ghcr.io/okedeji/researcher")
	if err := VerifyPull(sig2, "sha256:abc", "ghcr.io", "okedeji/researcher", nil); err != nil {
		t.Fatalf("re-pin after trust rm: %v", err)
	}
}

func TestExportImport_RoundTripAcrossHomes(t *testing.T) {
	setHome(t)
	orig, _, err := EnsureKey()
	if err != nil {
		t.Fatalf("EnsureKey: %v", err)
	}
	exported, err := ExportKey()
	if err != nil {
		t.Fatalf("ExportKey: %v", err)
	}

	// A second machine: fresh home, import, sign as the same publisher.
	setHome(t)
	imported, err := ImportKey(exported, false)
	if err != nil {
		t.Fatalf("ImportKey: %v", err)
	}
	if PublicKeyEncoded(imported.Public) != PublicKeyEncoded(orig.Public) {
		t.Fatal("imported key differs from exported")
	}
	loaded, ok, err := LoadKey()
	if err != nil || !ok {
		t.Fatalf("LoadKey after import: ok=%v err=%v", ok, err)
	}
	if PublicKeyEncoded(loaded.Public) != PublicKeyEncoded(orig.Public) {
		t.Fatal("persisted key differs from imported")
	}
}

func TestExportKey_NoneIsAnError(t *testing.T) {
	setHome(t)
	_, err := ExportKey()
	if err == nil || !strings.Contains(err.Error(), "no signing key") {
		t.Fatalf("err = %v, want a no-key error", err)
	}
}

func TestImportKey_ConflictNeedsForce(t *testing.T) {
	setHome(t)
	a, _, _ := EnsureKey()
	exportedA, _ := ExportKey()

	// Second home generates its own key B, then imports A.
	setHome(t)
	b, _, _ := EnsureKey()

	if _, err := ImportKey(exportedA, false); err == nil || !strings.Contains(err.Error(), "--force") {
		t.Fatalf("err = %v, want a conflict naming --force", err)
	}
	// Re-importing the installed key is a no-op, no force needed.
	exportedB, _ := ExportKey()
	if _, err := ImportKey(exportedB, false); err != nil {
		t.Fatalf("same-key import should be a no-op: %v", err)
	}
	// Force replaces.
	got, err := ImportKey(exportedA, true)
	if err != nil {
		t.Fatalf("forced import: %v", err)
	}
	if PublicKeyEncoded(got.Public) != PublicKeyEncoded(a.Public) || PublicKeyEncoded(got.Public) == PublicKeyEncoded(b.Public) {
		t.Fatal("forced import did not install the new key")
	}
}

func TestImportKey_GarbageFailsClosed(t *testing.T) {
	setHome(t)
	if _, err := ImportKey([]byte("not a key"), false); err == nil {
		t.Fatal("garbage must not import")
	}
}

func TestScope_FirstSegmentOnly(t *testing.T) {
	if got := Scope("ghcr.io", "okedeji/researcher"); got != "ghcr.io/okedeji" {
		t.Errorf("Scope = %q, want ghcr.io/okedeji", got)
	}
	if got := Scope("ghcr.io", "solo"); got != "ghcr.io/solo" {
		t.Errorf("Scope = %q, want ghcr.io/solo", got)
	}
}
