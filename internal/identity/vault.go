package identity

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	vaultapi "github.com/hashicorp/vault/api"
)

// SecretFetcher manages Vault authentication and secret retrieval for cages.
type SecretFetcher interface {
	Authenticate(ctx context.Context, svid *SVID) (*VaultToken, error)
	Fetch(ctx context.Context, token *VaultToken, path string) ([]byte, error)
	Revoke(ctx context.Context, token *VaultToken) error
}

// VaultClient implements SecretFetcher using HashiCorp Vault's HTTP API.
type VaultClient struct {
	client   *vaultapi.Client
	authPath string
	role     string
}

// NewVaultClient creates a Vault API client configured to authenticate via JWT.
func NewVaultClient(addr, authPath, role string) (*VaultClient, error) {
	cfg := vaultapi.DefaultConfig()
	cfg.Address = addr
	client, err := vaultapi.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("creating Vault client for %s: %w", addr, err)
	}
	return &VaultClient{client: client, authPath: authPath, role: role}, nil
}

// Production will use workloadapi.FetchJWTSVID to obtain a proper JWT-SVID
// for Vault authentication. Until the JWT SVID source is wired, we base64-encode
// the raw X.509 SVID bytes as a stand-in.
func (v *VaultClient) Authenticate(ctx context.Context, svid *SVID) (*VaultToken, error) {
	jwt := base64.StdEncoding.EncodeToString(svid.Raw)

	secret, err := v.client.Logical().WriteWithContext(ctx, v.authPath, map[string]interface{}{
		"role": v.role,
		"jwt":  jwt,
	})
	if err != nil {
		return nil, fmt.Errorf("authenticating cage %s with Vault at %s: %w", svid.CageID, v.authPath, err)
	}
	if secret == nil || secret.Auth == nil {
		return nil, fmt.Errorf("authenticating cage %s with Vault: empty auth response", svid.CageID)
	}

	ttl, err := secret.TokenTTL()
	if err != nil {
		return nil, fmt.Errorf("parsing Vault token TTL for cage %s: %w", svid.CageID, err)
	}

	return &VaultToken{
		Token:     secret.Auth.ClientToken,
		ExpiresAt: time.Now().Add(ttl),
		CageID:    svid.CageID,
		Policies:  secret.Auth.Policies,
	}, nil
}

func (v *VaultClient) Fetch(ctx context.Context, token *VaultToken, path string) ([]byte, error) {
	v.client.SetToken(token.Token)
	defer v.client.ClearToken()

	secret, err := v.client.Logical().ReadWithContext(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("reading Vault secret at %s for cage %s: %w", path, token.CageID, err)
	}
	if secret == nil || secret.Data == nil {
		return nil, fmt.Errorf("reading Vault secret at %s for cage %s: no data returned", path, token.CageID)
	}

	data, err := json.Marshal(secret.Data)
	if err != nil {
		return nil, fmt.Errorf("marshaling Vault secret data at %s for cage %s: %w", path, token.CageID, err)
	}

	return data, nil
}

func (v *VaultClient) Revoke(ctx context.Context, token *VaultToken) error {
	v.client.SetToken(token.Token)
	defer v.client.ClearToken()

	err := v.client.Auth().Token().RevokeSelfWithContext(ctx, "")
	if err != nil {
		// Idempotent: a 403 means the token is already revoked or invalid.
		if respErr, ok := err.(*vaultapi.ResponseError); ok && respErr.StatusCode == 403 {
			return nil
		}
		return fmt.Errorf("revoking Vault token for cage %s: %w", token.CageID, err)
	}
	return nil
}
