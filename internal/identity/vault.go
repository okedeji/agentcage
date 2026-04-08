package identity

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	vaultapi "github.com/hashicorp/vault/api"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

// SecretFetcher manages Vault authentication and secret retrieval for cages.
type SecretFetcher interface {
	Authenticate(ctx context.Context, svid *SVID) (*VaultToken, error)
	Fetch(ctx context.Context, token *VaultToken, path string) ([]byte, error)
	Revoke(ctx context.Context, token *VaultToken) error
}

// JWTSource issues JWT-SVIDs for cage workload identities. Implemented by
// the SPIRE workload API (production) and by stubs in tests.
type JWTSource interface {
	FetchJWTSVID(ctx context.Context, audience string) (*jwtsvid.SVID, error)
	Close() error
}

// VaultClient implements SecretFetcher using HashiCorp Vault's HTTP
// API. The embedded *vaultapi.Client is a template; every per-cage
// call clones it so SetToken doesn't race across goroutines. Exactly
// one of jwtSource (production) or staticToken (dev) is set.
type VaultClient struct {
	template    *vaultapi.Client
	authPath    string
	role        string
	jwtSource   JWTSource
	audience    string
	staticToken string
}

// VaultJWTConfig configures a Vault client that authenticates each cage via
// a real JWT-SVID issued by SPIRE. This is the production path.
type VaultJWTConfig struct {
	Address   string
	AuthPath  string      // e.g. "auth/jwt/login"
	Role      string      // Vault JWT auth role bound to the cage SPIFFE ID
	TLS       *tls.Config // nil falls back to system trust store
	JWTSource JWTSource   // required
	Audience  string      // SPIFFE audience claim; defaults to "vault"
}

// VaultTokenConfig configures a Vault client that uses a fixed root
// or service token. The embedded dev-mode path: `vault server -dev`
// emits a known token, the orchestrator hands it to every cage, and
// Authenticate becomes a no-op.
//
// Never use this against production Vault. Every cage gets the same
// token with the same policies.
type VaultTokenConfig struct {
	Address string
	TLS     *tls.Config
	Token   string // required
}

func (c VaultTokenConfig) String() string {
	return fmt.Sprintf("VaultTokenConfig{address=%s, token=REDACTED}", c.Address)
}

func (c VaultTokenConfig) GoString() string {
	return fmt.Sprintf("identity.VaultTokenConfig{Address:%q, Token:REDACTED}", c.Address)
}

func (c VaultTokenConfig) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Address string `json:"address"`
		Token   string `json:"token"`
	}{
		Address: c.Address,
		Token:   "REDACTED",
	})
}

// NewVaultJWTClient creates a Vault client that authenticates cages with
// JWT-SVIDs from SPIRE. Call Health(ctx) after construction to verify
// reachability.
func NewVaultJWTClient(cfg VaultJWTConfig) (*VaultClient, error) {
	if cfg.JWTSource == nil {
		return nil, fmt.Errorf("vault jwt client: JWTSource is required")
	}
	template, err := buildVaultAPIClient(cfg.Address, cfg.TLS)
	if err != nil {
		return nil, err
	}
	audience := cfg.Audience
	if audience == "" {
		audience = "vault"
	}
	return &VaultClient{
		template:  template,
		authPath:  cfg.AuthPath,
		role:      cfg.Role,
		jwtSource: cfg.JWTSource,
		audience:  audience,
	}, nil
}

// NewVaultTokenClient creates a Vault client that issues every cage the same
// fixed token. Embedded dev mode only.
func NewVaultTokenClient(cfg VaultTokenConfig) (*VaultClient, error) {
	if cfg.Token == "" {
		return nil, fmt.Errorf("vault token client: Token is required")
	}
	template, err := buildVaultAPIClient(cfg.Address, cfg.TLS)
	if err != nil {
		return nil, err
	}
	return &VaultClient{
		template:    template,
		staticToken: cfg.Token,
	}, nil
}

func buildVaultAPIClient(addr string, tlsCfg *tls.Config) (*vaultapi.Client, error) {
	apiCfg := vaultapi.DefaultConfig()
	apiCfg.Address = addr
	if tlsCfg != nil {
		transport, ok := apiCfg.HttpClient.Transport.(*http.Transport)
		if !ok {
			return nil, fmt.Errorf("vault default transport is not *http.Transport")
		}
		transport.TLSClientConfig = tlsCfg
	}
	client, err := vaultapi.NewClient(apiCfg)
	if err != nil {
		return nil, fmt.Errorf("creating Vault client for %s: %w", addr, err)
	}
	return client, nil
}

// Health calls Vault's /sys/health endpoint. Used at orchestrator startup so
// a wrong address or TLS misconfiguration fails loudly instead of bleeding
// into the first cage provision.
func (v *VaultClient) Health(ctx context.Context) error {
	c := v.cloneClient()
	_, err := c.Sys().HealthWithContext(ctx)
	if err != nil {
		return fmt.Errorf("vault health check: %w", err)
	}
	return nil
}

// cloneClient returns a per-call copy of the underlying Vault client.
// Clone() shares Address, TLS, and HTTP transport, but each clone has
// its own token slot, so SetToken on one goroutine doesn't leak into
// another.
func (v *VaultClient) cloneClient() *vaultapi.Client {
	c, err := v.template.Clone()
	if err != nil {
		// Clone() only fails on programmer error (nil client). Return
		// the template instead of crashing; worst case is the
		// SetToken race we're trying to fix.
		return v.template
	}
	return c
}

func (v *VaultClient) Authenticate(ctx context.Context, svid *SVID) (*VaultToken, error) {
	// Embedded dev mode: hand back the same static token for every cage.
	// LookupSelf gives us the real TTL and policy list so callers see the
	// same shape they would in JWT mode.
	if v.staticToken != "" {
		c := v.cloneClient()
		c.SetToken(v.staticToken)
		secret, err := c.Auth().Token().LookupSelfWithContext(ctx)
		if err != nil {
			return nil, fmt.Errorf("looking up static vault token for cage %s: %w", svid.CageID, err)
		}

		token := &VaultToken{
			Token:  v.staticToken,
			CageID: svid.CageID,
		}
		if ttl, ok := secret.Data["ttl"].(json.Number); ok {
			if seconds, err := ttl.Int64(); err == nil && seconds > 0 {
				token.ExpiresAt = time.Now().Add(time.Duration(seconds) * time.Second)
			}
		}
		if policies, ok := secret.Data["policies"].([]interface{}); ok {
			for _, p := range policies {
				if s, ok := p.(string); ok {
					token.Policies = append(token.Policies, s)
				}
			}
		}
		return token, nil
	}

	if v.jwtSource == nil {
		return nil, fmt.Errorf("vault: no auth method configured for cage %s", svid.CageID)
	}

	// Fetch a real JWT-SVID scoped to this cage's workload identity. Vault
	// validates the signature against its trust bundle (the SPIRE upstream)
	// and looks up the role's policies via the audience claim.
	jwt, err := v.jwtSource.FetchJWTSVID(ctx, v.audience)
	if err != nil {
		return nil, fmt.Errorf("fetching JWT-SVID for cage %s: %w", svid.CageID, err)
	}

	c := v.cloneClient()
	secret, err := c.Logical().WriteWithContext(ctx, v.authPath, map[string]interface{}{
		"role": v.role,
		"jwt":  jwt.Marshal(),
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
	c := v.cloneClient()
	c.SetToken(token.Token)

	secret, err := c.Logical().ReadWithContext(ctx, path)
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
	c := v.cloneClient()
	c.SetToken(token.Token)

	err := c.Auth().Token().RevokeSelfWithContext(ctx, "")
	if err != nil {
		// Idempotent: a 403 means the token is already revoked or invalid.
		if respErr, ok := err.(*vaultapi.ResponseError); ok && respErr.StatusCode == 403 {
			return nil
		}
		return fmt.Errorf("revoking Vault token for cage %s: %w", token.CageID, err)
	}
	return nil
}

// NewSpireJWTSource opens a workloadapi JWT source against the given SPIRE
// socket. Caller must Close() it at shutdown.
func NewSpireJWTSource(ctx context.Context, socketPath string) (JWTSource, error) {
	src, err := workloadapi.NewJWTSource(ctx, workloadapi.WithClientOptions(
		workloadapi.WithAddr("unix://"+socketPath),
	))
	if err != nil {
		return nil, fmt.Errorf("opening SPIRE JWT source at %s: %w", socketPath, err)
	}
	return &spireJWTAdapter{src: src}, nil
}

type spireJWTAdapter struct {
	src *workloadapi.JWTSource
}

func (a *spireJWTAdapter) FetchJWTSVID(ctx context.Context, audience string) (*jwtsvid.SVID, error) {
	return a.src.FetchJWTSVID(ctx, jwtsvid.Params{Audience: audience})
}

func (a *spireJWTAdapter) Close() error {
	return a.src.Close()
}

