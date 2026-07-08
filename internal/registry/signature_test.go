package registry

import (
	"context"
	"strings"
	"testing"

	"oras.land/oras-go/v2/content/memory"

	"github.com/okedeji/agentcage/internal/env"
	"github.com/okedeji/agentcage/internal/reference"
	"github.com/okedeji/agentcage/internal/signing"
)

func mustParseRef(t *testing.T, s string) reference.Reference {
	t.Helper()
	ref, err := reference.Parse(s)
	if err != nil {
		t.Fatalf("Parse(%q): %v", s, err)
	}
	return ref
}

func TestSignatureTag(t *testing.T) {
	got := signatureTag("sha256:abc123")
	if got != "sha256-abc123.sig" {
		t.Errorf("signatureTag = %q, want sha256-abc123.sig", got)
	}
}

func TestPushFetchSignature_RoundTrip(t *testing.T) {
	t.Setenv(env.Home, t.TempDir())
	key, _, err := signing.EnsureKey()
	if err != nil {
		t.Fatalf("EnsureKey: %v", err)
	}
	sig, err := signing.Sign(key, "sha256:abc", "ghcr.io/okedeji/researcher")
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	dst := memory.New()
	if err := pushSignature(context.Background(), dst, "sha256:abc", sig); err != nil {
		t.Fatalf("pushSignature: %v", err)
	}

	got, ok, err := fetchSignature(context.Background(), dst, "sha256:abc")
	if err != nil {
		t.Fatalf("fetchSignature: %v", err)
	}
	if !ok {
		t.Fatal("signature was pushed; fetch should find it")
	}
	if string(got) != string(sig) {
		t.Error("fetched signature differs from pushed")
	}

	if _, err := signing.Verify(got, "sha256:abc", "ghcr.io/okedeji/researcher"); err != nil {
		t.Errorf("fetched signature should verify: %v", err)
	}
}

func TestFetchSignature_AbsentIsNotAnError(t *testing.T) {
	_, ok, err := fetchSignature(context.Background(), memory.New(), "sha256:nothing")
	if err != nil {
		t.Fatalf("fetchSignature: %v", err)
	}
	if ok {
		t.Fatal("no signature exists; ok must be false")
	}
}

func TestRequireSignatures_Values(t *testing.T) {
	t.Setenv(env.Home, t.TempDir())
	cases := map[string]bool{"": false, "0": false, "false": false, "1": true, "true": true, "yes": true}
	for v, want := range cases {
		t.Setenv(env.RequireSignatures, v)
		if got := requireSignatures(); got != want {
			t.Errorf("requireSignatures(%q) = %v, want %v", v, got, want)
		}
	}
}

func TestVerifyPulled_UnsignedFailsClosedUnderRequire(t *testing.T) {
	t.Setenv(env.Home, t.TempDir())
	t.Setenv(env.RequireSignatures, "1")

	c := &Client{}
	ref := mustParseRef(t, "@okedeji/researcher:0.1")
	err := c.verifyPulled(context.Background(), memory.New(), ref, "sha256:abc")
	if err == nil || !strings.Contains(err.Error(), "not signed") {
		t.Fatalf("err = %v, want an unsigned rejection under AGENTCAGE_REQUIRE_SIGNATURES", err)
	}
}

func TestVerifyPulled_SignedRoundTripThroughPolicy(t *testing.T) {
	t.Setenv(env.Home, t.TempDir())
	key, _, _ := signing.EnsureKey()

	ref := mustParseRef(t, "@okedeji/researcher:0.1")
	repoFull := ref.Registry + "/" + ref.Repository
	sig, _ := signing.Sign(key, "sha256:abc", repoFull)

	dst := memory.New()
	if err := pushSignature(context.Background(), dst, "sha256:abc", sig); err != nil {
		t.Fatalf("pushSignature: %v", err)
	}

	var notices []string
	c := &Client{Notify: func(format string, args ...any) { notices = append(notices, format) }}
	if err := c.verifyPulled(context.Background(), dst, ref, "sha256:abc"); err != nil {
		t.Fatalf("verifyPulled: %v", err)
	}
	if len(notices) == 0 {
		t.Error("a first verified pull should emit a pin notice")
	}
}
