package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/go-logr/logr"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"

	"github.com/okedeji/agentcage/internal/config"
	"github.com/okedeji/agentcage/internal/embedded"
	"github.com/okedeji/agentcage/internal/identity"
)

func resolveSpireSocket(cfg *config.Config) string {
	socket := filepath.Join(embedded.RunDir(), "spire", "agent.sock")
	if cfg.Infrastructure.IsExternalSPIRE() && cfg.Infrastructure.SPIRE.AgentSocket != "" {
		socket = cfg.Infrastructure.SPIRE.AgentSocket
	}
	return socket
}

// A healthy Vault answers in well under a second; a wedged one hangs boot.
const vaultHealthTimeout = 5 * time.Second

// SPIRE first because Vault JWT auth needs a JWT-SVID from SPIRE.
// Either return can be nil in dev; strict posture rejects nil at
// the call site.
func connectIdentityAndSecrets(
	ctx context.Context,
	cfg *config.Config,
	embeddedMgr *embedded.Manager,
	spireSocket string,
	log logr.Logger,
) (identity.SVIDIssuer, identity.SecretFetcher, identity.SecretReader, func(), error) {
	cleanups := []func(){}
	cleanup := func() {
		// LIFO, like stacked defers.
		for i := len(cleanups) - 1; i >= 0; i-- {
			cleanups[i]()
		}
	}

	fmt.Println("Connecting to identity and secrets services...")

	var svidIssuer identity.SVIDIssuer
	if _, socketErr := os.Stat(spireSocket); socketErr == nil {
		spireClient, spireErr := identity.NewSpireClient(ctx, spireSocket, "agentcage.local")
		if spireErr != nil {
			log.Error(spireErr, "connecting to SPIRE, cages will use dev identities")
		} else {
			svidIssuer = spireClient
			cleanups = append(cleanups, func() { _ = spireClient.Close() })
			log.Info("SPIRE identity issuer connected", "socket", spireSocket)
		}
	}
	if svidIssuer == nil {
		log.Info("SPIRE not available, cages will use dev identities")
	}

	secretFetcher, secretReader, err := buildSecretFetcher(ctx, cfg, embeddedMgr, spireSocket, &cleanups, log)
	if err != nil {
		cleanup()
		return nil, nil, nil, nil, err
	}

	if secretFetcher == nil {
		if !cfg.AllowUnisolatedDefault() {
			cleanup()
			return nil, nil, nil, nil, fmt.Errorf("no Vault configured: set infrastructure.vault.address, enable embedded Vault, or set cage_runtime.allow_unisolated=true for dev-mode secrets")
		}
		log.Info("WARNING: Vault not configured, cages will use dev secrets (allow_unisolated=true)")
	}

	return svidIssuer, secretFetcher, secretReader, cleanup, nil
}

func buildSecretFetcher(
	ctx context.Context,
	cfg *config.Config,
	embeddedMgr *embedded.Manager,
	spireSocket string,
	cleanups *[]func(),
	log logr.Logger,
) (identity.SecretFetcher, identity.SecretReader, error) {
	if cfg.Infrastructure.IsExternalVault() {
		fetcher, err := buildVaultJWTClient(ctx, cfg, spireSocket, cleanups, log)
		if err != nil {
			return nil, nil, err
		}
		reader, err := buildOrchestratorSecretReader(ctx, cfg, spireSocket, cleanups, log)
		if err != nil {
			return nil, nil, err
		}
		return fetcher, reader, nil
	}
	if embeddedVault := embeddedMgr.EmbeddedVault(); embeddedVault != nil {
		fetcher, err := buildEmbeddedVaultClient(ctx, embeddedVault, log)
		if err != nil {
			return nil, nil, err
		}
		reader, err := identity.NewVaultTokenSecretReader(embeddedVault.Address(), embeddedVault.RootToken(), nil)
		if err != nil {
			return nil, nil, fmt.Errorf("creating embedded Vault secret reader: %w", err)
		}
		log.Info("orchestrator secret reader connected (embedded dev token)")
		return fetcher, reader, nil
	}
	return nil, nil, nil
}

// The orchestrator authenticates to Vault with its own SPIRE SVID using
// a dedicated role ("orchestrator") that grants read access to
// secret/agentcage/orchestrator/* and secret/agentcage/target/*.
// Separate from the cage role which only accesses secret/cage/{cageID}/*.
func buildOrchestratorSecretReader(
	ctx context.Context,
	cfg *config.Config,
	spireSocket string,
	cleanups *[]func(),
	log logr.Logger,
) (identity.SecretReader, error) {
	vaultCfg := cfg.Infrastructure.Vault
	authPath := vaultCfg.AuthPath
	if authPath == "" {
		authPath = "auth/jwt/login"
	}
	role := vaultCfg.OrchestratorRole
	if role == "" {
		role = "orchestrator"
	}

	tlsCfg, err := buildVaultTLSConfig(ctx, cfg, spireSocket)
	if err != nil {
		return nil, fmt.Errorf("building Vault TLS config for orchestrator reader: %w", err)
	}

	jwtSource, err := identity.NewSpireJWTSource(ctx, spireSocket)
	if err != nil {
		return nil, fmt.Errorf("opening SPIRE JWT source for orchestrator Vault auth: %w", err)
	}
	*cleanups = append(*cleanups, func() { _ = jwtSource.Close() })

	reader, err := identity.NewVaultJWTSecretReader(identity.VaultJWTReaderConfig{
		Address:   vaultCfg.Address,
		AuthPath:  authPath,
		Role:      role,
		TLS:       tlsCfg,
		JWTSource: jwtSource,
	})
	if err != nil {
		return nil, fmt.Errorf("creating orchestrator Vault reader: %w", err)
	}

	log.Info("orchestrator secret reader connected (jwt mode)",
		"addr", vaultCfg.Address,
		"role", role,
	)
	return reader, nil
}

// Production path. Vault JWT auth role scopes each cage's token
// to its SPIFFE identity.
func buildVaultJWTClient(
	ctx context.Context,
	cfg *config.Config,
	spireSocket string,
	cleanups *[]func(),
	log logr.Logger,
) (identity.SecretFetcher, error) {
	vaultCfg := cfg.Infrastructure.Vault
	authPath := vaultCfg.AuthPath
	if authPath == "" {
		authPath = "auth/jwt/login"
	}
	role := vaultCfg.Role
	if role == "" {
		role = "cage"
	}

	tlsCfg, tlsErr := buildVaultTLSConfig(ctx, cfg, spireSocket)
	if tlsErr != nil {
		return nil, fmt.Errorf("building Vault TLS config: %w", tlsErr)
	}

	jwtSource, jwtErr := identity.NewSpireJWTSource(ctx, spireSocket)
	if jwtErr != nil {
		return nil, fmt.Errorf("opening SPIRE JWT source for Vault auth: %w", jwtErr)
	}
	*cleanups = append(*cleanups, func() { _ = jwtSource.Close() })

	vaultClient, vaultErr := identity.NewVaultJWTClient(identity.VaultJWTConfig{
		Address:   vaultCfg.Address,
		AuthPath:  authPath,
		Role:      role,
		TLS:       tlsCfg,
		JWTSource: jwtSource,
		Audience:  "vault",
	})
	if vaultErr != nil {
		return nil, fmt.Errorf("creating Vault client: %w", vaultErr)
	}

	healthCtx, cancelHealth := context.WithTimeout(ctx, vaultHealthTimeout)
	defer cancelHealth()
	if err := vaultClient.Health(healthCtx); err != nil {
		return nil, fmt.Errorf("vault unreachable at %s: %w", vaultCfg.Address, err)
	}

	log.Info("Vault secret fetcher connected (jwt mode)",
		"addr", vaultCfg.Address,
		"auth_path", authPath,
		"role", role,
		"tls", vaultTLSMode(cfg))
	return vaultClient, nil
}

// Dev path. Shared root token is fine on a laptop where the host
// trust boundary already dominates anything Vault would enforce.
func buildEmbeddedVaultClient(
	ctx context.Context,
	embeddedVault *embedded.VaultService,
	log logr.Logger,
) (identity.SecretFetcher, error) {
	vaultClient, vaultErr := identity.NewVaultTokenClient(identity.VaultTokenConfig{
		Address: embeddedVault.Address(),
		Token:   embeddedVault.RootToken(),
	})
	if vaultErr != nil {
		return nil, fmt.Errorf("creating embedded Vault client: %w", vaultErr)
	}

	healthCtx, cancelHealth := context.WithTimeout(ctx, vaultHealthTimeout)
	defer cancelHealth()
	if err := vaultClient.Health(healthCtx); err != nil {
		return nil, fmt.Errorf("embedded vault unreachable at %s: %w", embeddedVault.Address(), err)
	}

	log.Info("Vault secret fetcher connected (embedded dev token)", "addr", embeddedVault.Address())
	return vaultClient, nil
}

func buildVaultTLSConfig(ctx context.Context, cfg *config.Config, spireSocket string) (*tls.Config, error) {
	vaultCfg := cfg.Infrastructure.Vault
	if vaultCfg == nil || vaultCfg.TLS == nil {
		return nil, nil
	}
	t := vaultCfg.TLS

	if cfg.VaultSkipVerifyDefault() {
		return &tls.Config{InsecureSkipVerify: true}, nil //nolint:gosec // explicit operator opt-in; rejected by validatePosture in strict mode
	}

	if t.Internal {
		source, err := workloadapi.NewX509Source(ctx, workloadapi.WithClientOptions(
			workloadapi.WithAddr("unix://"+spireSocket),
		))
		if err != nil {
			return nil, fmt.Errorf("opening SPIRE X.509 source for Vault TLS: %w", err)
		}
		// Any SVID from our trust domain is accepted as Vault. Pin a
		// specific SPIFFE ID here if the trust domain ever holds more
		// than one Vault.
		return tlsconfig.MTLSClientConfig(source, source, tlsconfig.AuthorizeAny()), nil
	}

	if t.CACertFile != "" {
		caBytes, err := os.ReadFile(t.CACertFile)
		if err != nil {
			return nil, fmt.Errorf("reading vault ca_cert_file %s: %w", t.CACertFile, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caBytes) {
			return nil, fmt.Errorf("vault ca_cert_file %s: no PEM certs found", t.CACertFile)
		}
		return &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}, nil
	}

	return nil, nil
}

// vaultTLSMode is a short label for startup log lines so operators
// don't have to grep config.
func vaultTLSMode(cfg *config.Config) string {
	vaultCfg := cfg.Infrastructure.Vault
	if vaultCfg == nil || vaultCfg.TLS == nil {
		return "system"
	}
	switch {
	case cfg.VaultSkipVerifyDefault():
		return "insecure-skip-verify"
	case vaultCfg.TLS.Internal:
		return "spire-internal"
	case vaultCfg.TLS.CACertFile != "":
		return "ca-pinned"
	default:
		return "system"
	}
}
