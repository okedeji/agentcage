package identity

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stubJWTSource returns a fixed token string. Tests don't need a real signed
// JWT-SVID because the mock Vault server doesn't verify it.
type stubJWTSource struct{}

func (stubJWTSource) FetchJWTSVID(_ context.Context, _ string) (*jwtsvid.SVID, error) {
	// jwtsvid.ParseInsecure on a minimal-but-syntactically-valid token —
	// header.payload.sig with empty payload — gives us a *jwtsvid.SVID
	// whose Marshal() returns the same string we pass to Vault.
	tok := "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJzcGlmZmU6Ly9leGFtcGxlLm9yZy9jYWdlL3Rlc3QiLCJhdWQiOlsidmF1bHQiXSwiZXhwIjo5OTk5OTk5OTk5fQ.sig"
	svid, err := jwtsvid.ParseInsecure(tok, []string{"vault"})
	if err != nil {
		return nil, err
	}
	return svid, nil
}

func (stubJWTSource) Close() error { return nil }

func newTestVaultClient(t *testing.T, addr string) *VaultClient {
	t.Helper()
	vc, err := NewVaultJWTClient(VaultJWTConfig{
		Address:   addr,
		AuthPath:  "auth/jwt/login",
		Role:      "cage-role",
		JWTSource: stubJWTSource{},
		Audience:  "vault",
	})
	require.NoError(t, err)
	return vc
}

func newMockVaultServer(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	return httptest.NewServer(handler)
}

func TestVaultClient_Authenticate_Success(t *testing.T) {
	server := newMockVaultServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/auth/jwt/login" && r.Method == http.MethodPut {
			resp := map[string]interface{}{
				"auth": map[string]interface{}{
					"client_token": "s.test-token-123",
					"policies":     []string{"cage-default", "cage-discovery"},
					"lease_duration": 3600,
					"renewable":      true,
				},
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})
	defer server.Close()

	vc := newTestVaultClient(t, server.URL)
	svid := &SVID{
		ID:        "test-serial",
		SpiffeID:  "spiffe://example.org/cage/test-cage-1",
		Raw:       []byte("test-cert-bytes"),
		ExpiresAt: time.Now().Add(time.Hour),
		CageID:    "test-cage-1",
	}

	token, err := vc.Authenticate(context.Background(), svid)
	require.NoError(t, err)

	assert.Equal(t, "s.test-token-123", token.Token)
	assert.Equal(t, "test-cage-1", token.CageID)
	assert.Contains(t, token.Policies, "cage-default")
	assert.Contains(t, token.Policies, "cage-discovery")
	assert.True(t, token.ExpiresAt.After(time.Now()))
}

func TestVaultClient_Authenticate_Rejected(t *testing.T) {
	server := newMockVaultServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"errors": []string{"permission denied"},
		})
	})
	defer server.Close()

	vc := newTestVaultClient(t, server.URL)
	svid := &SVID{
		ID:       "test-serial",
		Raw:      []byte("bad-cert"),
		CageID:   "test-cage-1",
	}

	_, err := vc.Authenticate(context.Background(), svid)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "authenticating cage test-cage-1")
}

func TestVaultClient_Fetch_Success(t *testing.T) {
	server := newMockVaultServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/secret/data/cage/test-cage-1/api-key" && r.Method == http.MethodGet {
			resp := map[string]interface{}{
				"data": map[string]interface{}{
					"api_key":  "sk-test-key",
					"provider": "openai",
				},
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})
	defer server.Close()

	vc := newTestVaultClient(t, server.URL)
	token := &VaultToken{
		Token:    "s.valid-token",
		CageID:   "test-cage-1",
		Policies: []string{"cage-default"},
	}

	data, err := vc.Fetch(context.Background(), token, "secret/data/cage/test-cage-1/api-key")
	require.NoError(t, err)

	var parsed map[string]interface{}
	err = json.Unmarshal(data, &parsed)
	require.NoError(t, err)
	assert.Equal(t, "sk-test-key", parsed["api_key"])
	assert.Equal(t, "openai", parsed["provider"])
}

func TestVaultClient_Fetch_Forbidden(t *testing.T) {
	server := newMockVaultServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"errors": []string{"permission denied"},
		})
	})
	defer server.Close()

	vc := newTestVaultClient(t, server.URL)
	token := &VaultToken{
		Token:  "s.revoked-token",
		CageID: "test-cage-1",
	}

	_, err := vc.Fetch(context.Background(), token, "secret/data/cage/test-cage-1/api-key")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "reading Vault secret")
}

func TestVaultClient_Revoke_Success(t *testing.T) {
	server := newMockVaultServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/auth/token/revoke-self" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})
	defer server.Close()

	vc := newTestVaultClient(t, server.URL)
	token := &VaultToken{
		Token:  "s.valid-token",
		CageID: "test-cage-1",
	}

	err := vc.Revoke(context.Background(), token)
	assert.NoError(t, err)
}

func TestVaultClient_Revoke_AlreadyRevoked(t *testing.T) {
	server := newMockVaultServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/auth/token/revoke-self" {
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"errors": []string{"permission denied"},
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})
	defer server.Close()

	vc := newTestVaultClient(t, server.URL)
	token := &VaultToken{
		Token:  "s.already-revoked",
		CageID: "test-cage-1",
	}

	err := vc.Revoke(context.Background(), token)
	assert.NoError(t, err)
}
