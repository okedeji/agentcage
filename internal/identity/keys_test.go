package identity

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockFetcher struct {
	secrets    map[string][]byte
	fetchCount atomic.Int64
}

func (m *mockFetcher) Authenticate(_ context.Context, _ *SVID) (*VaultToken, error) {
	return &VaultToken{Token: "test", CageID: "test"}, nil
}

func (m *mockFetcher) Fetch(_ context.Context, _ *VaultToken, path string) ([]byte, error) {
	m.fetchCount.Add(1)
	val, ok := m.secrets[path]
	if !ok {
		return nil, fmt.Errorf("secret not found: %s", path)
	}
	return val, nil
}

func (m *mockFetcher) Revoke(_ context.Context, _ *VaultToken) error {
	return nil
}

func TestVaultKeyResolver_ExistingKey(t *testing.T) {
	fetcher := &mockFetcher{
		secrets: map[string][]byte{
			"secret/signing-keys/v1": []byte("key-material-v1"),
		},
	}
	token := &VaultToken{Token: "test-token", CageID: "cage-1"}
	resolve := NewVaultKeyResolver(fetcher, token, "secret/signing-keys")

	key, err := resolve("v1")
	require.NoError(t, err)
	assert.Equal(t, []byte("key-material-v1"), key)
}

func TestVaultKeyResolver_UnknownVersion(t *testing.T) {
	fetcher := &mockFetcher{
		secrets: map[string][]byte{},
	}
	token := &VaultToken{Token: "test-token", CageID: "cage-1"}
	resolve := NewVaultKeyResolver(fetcher, token, "secret/signing-keys")

	_, err := resolve("v99")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "v99")
	assert.Contains(t, err.Error(), "fetching signing key version")
}

func TestVaultKeyResolver_CacheHit(t *testing.T) {
	fetcher := &mockFetcher{
		secrets: map[string][]byte{
			"secret/signing-keys/v1": []byte("key-material-v1"),
		},
	}
	token := &VaultToken{Token: "test-token", CageID: "cage-1"}
	resolve := NewVaultKeyResolver(fetcher, token, "secret/signing-keys")

	key1, err := resolve("v1")
	require.NoError(t, err)

	key2, err := resolve("v1")
	require.NoError(t, err)

	assert.Equal(t, key1, key2)
	assert.Equal(t, int64(1), fetcher.fetchCount.Load())
}

func TestVaultKeyResolver_MultipleVersions(t *testing.T) {
	fetcher := &mockFetcher{
		secrets: map[string][]byte{
			"secret/signing-keys/v1": []byte("key-material-v1"),
			"secret/signing-keys/v2": []byte("key-material-v2"),
		},
	}
	token := &VaultToken{Token: "test-token", CageID: "cage-1"}
	resolve := NewVaultKeyResolver(fetcher, token, "secret/signing-keys")

	key1, err := resolve("v1")
	require.NoError(t, err)

	key2, err := resolve("v2")
	require.NoError(t, err)

	assert.Equal(t, []byte("key-material-v1"), key1)
	assert.Equal(t, []byte("key-material-v2"), key2)
	assert.NotEqual(t, key1, key2)
	assert.Equal(t, int64(2), fetcher.fetchCount.Load())
}
