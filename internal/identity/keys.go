package identity

import (
	"context"
	"fmt"
	"sync"

	"github.com/okedeji/agentcage/internal/audit"
)

func NewVaultKeyResolver(fetcher SecretFetcher, token *VaultToken, basePath string) audit.KeyResolver {
	var cache sync.Map

	return func(keyVersion string) ([]byte, error) {
		if cached, ok := cache.Load(keyVersion); ok {
			return cached.([]byte), nil
		}

		path := basePath + "/" + keyVersion

		// KeyResolver's function signature doesn't accept a context.
		// Vault calls here are infrequent (once per key version, then cached)
		// and non-cancellable by design — chain verification must complete
		// regardless of the caller's context state.
		key, err := fetcher.Fetch(context.Background(), token, path)
		if err != nil {
			return nil, fmt.Errorf("fetching signing key version %s from Vault: %w", keyVersion, err)
		}

		cache.Store(keyVersion, key)
		return key, nil
	}
}
