package identity

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// SVID represents a SPIFFE Verifiable Identity Document issued via SPIRE
// for a cage workload. Raw contains the X.509 certificate bytes and must
// never appear in logs or serialized output.
type SVID struct {
	ID        string
	SpiffeID  string
	Raw       []byte
	ExpiresAt time.Time
	CageID    string
}

func (s SVID) String() string {
	return fmt.Sprintf(
		"SVID{id=%s, spiffe_id=%s, raw=REDACTED, expires_at=%s, cage_id=%s}",
		s.ID, s.SpiffeID, s.ExpiresAt.Format(time.RFC3339), s.CageID,
	)
}

func (s SVID) GoString() string {
	return fmt.Sprintf(
		"identity.SVID{ID:%q, SpiffeID:%q, Raw:REDACTED, ExpiresAt:%s, CageID:%q}",
		s.ID, s.SpiffeID, s.ExpiresAt.Format(time.RFC3339), s.CageID,
	)
}

func (s SVID) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		ID        string    `json:"id"`
		SpiffeID  string    `json:"spiffe_id"`
		Raw       string    `json:"raw"`
		ExpiresAt time.Time `json:"expires_at"`
		CageID    string    `json:"cage_id"`
	}{
		ID:        s.ID,
		SpiffeID:  s.SpiffeID,
		Raw:       "REDACTED",
		ExpiresAt: s.ExpiresAt,
		CageID:    s.CageID,
	})
}

// VaultToken holds a Vault access token and its associated metadata.
// Token is the secret credential and must never appear in logs or
// serialized output.
type VaultToken struct {
	Token     string
	ExpiresAt time.Time
	CageID    string
	Policies  []string
}

func (t VaultToken) String() string {
	return fmt.Sprintf(
		"VaultToken{token=REDACTED, expires_at=%s, cage_id=%s, policies=[%s]}",
		t.ExpiresAt.Format(time.RFC3339), t.CageID, strings.Join(t.Policies, ", "),
	)
}

func (t VaultToken) GoString() string {
	return fmt.Sprintf(
		"identity.VaultToken{Token:REDACTED, ExpiresAt:%s, CageID:%q, Policies:%v}",
		t.ExpiresAt.Format(time.RFC3339), t.CageID, t.Policies,
	)
}

func (t VaultToken) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Token     string    `json:"token"`
		ExpiresAt time.Time `json:"expires_at"`
		CageID    string    `json:"cage_id"`
		Policies  []string  `json:"policies"`
	}{
		Token:     "REDACTED",
		ExpiresAt: t.ExpiresAt,
		CageID:    t.CageID,
		Policies:  t.Policies,
	})
}

// APIKey holds a provider API key used by the LLM gateway to authenticate
// outbound requests. Key is the secret credential and must never appear
// in logs or serialized output.
type APIKey struct {
	Key       string
	Provider  string
	ExpiresAt time.Time
}

func (k APIKey) String() string {
	return fmt.Sprintf(
		"APIKey{key=REDACTED, provider=%s, expires_at=%s}",
		k.Provider, k.ExpiresAt.Format(time.RFC3339),
	)
}

func (k APIKey) GoString() string {
	return fmt.Sprintf(
		"identity.APIKey{Key:REDACTED, Provider:%q, ExpiresAt:%s}",
		k.Provider, k.ExpiresAt.Format(time.RFC3339),
	)
}

func (k APIKey) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Key       string    `json:"key"`
		Provider  string    `json:"provider"`
		ExpiresAt time.Time `json:"expires_at"`
	}{
		Key:       "REDACTED",
		Provider:  k.Provider,
		ExpiresAt: k.ExpiresAt,
	})
}
