package audit

import (
	"errors"
	"fmt"
	"sort"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testResolver(keys map[string][]byte) KeyResolver {
	return func(version string) ([]byte, error) {
		key, ok := keys[version]
		if !ok {
			return nil, fmt.Errorf("unknown key version: %s", version)
		}
		return key, nil
	}
}

var (
	testKeyV1 = []byte("test-key-v1")
	testKeyV2 = []byte("test-key-v2")
)

func TestChain_BuildAndVerify(t *testing.T) {
	chain := NewChain("cage-1", "assess-1", "v1", testKeyV1)
	resolver := testResolver(map[string][]byte{"v1": testKeyV1})

	entries := make([]Entry, 0, 10)
	types := []EntryType{
		EntryTypeCageProvisioned,
		EntryTypeCageStarted,
		EntryTypePolicyApplied,
		EntryTypeEgressAllowed,
		EntryTypePayloadAllowed,
		EntryTypeFindingEmitted,
		EntryTypeTripwireFired,
		EntryTypeInterventionRequested,
		EntryTypeInterventionResolved,
		EntryTypeCageTornDown,
	}

	for i, et := range types {
		e, err := chain.Append(et, []byte(fmt.Sprintf("data-%d", i)))
		require.NoError(t, err)
		entries = append(entries, e)
	}

	require.NoError(t, VerifyChain(entries, resolver))
	assert.Equal(t, int64(10), chain.Sequence())
}

func TestChain_TamperData(t *testing.T) {
	chain := NewChain("cage-1", "assess-1", "v1", testKeyV1)
	resolver := testResolver(map[string][]byte{"v1": testKeyV1})

	entries := buildEntries(t, chain, 10)

	entries[4].Data = []byte("tampered")

	err := VerifyChain(entries, resolver)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrSignatureMismatch))
}

func TestChain_TamperSignature(t *testing.T) {
	chain := NewChain("cage-1", "assess-1", "v1", testKeyV1)
	resolver := testResolver(map[string][]byte{"v1": testKeyV1})

	entries := buildEntries(t, chain, 10)

	entries[2].Signature[0] ^= 0xff

	err := VerifyChain(entries, resolver)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrSignatureMismatch))
}

func TestChain_DeleteMiddleEntry(t *testing.T) {
	chain := NewChain("cage-1", "assess-1", "v1", testKeyV1)
	resolver := testResolver(map[string][]byte{"v1": testKeyV1})

	entries := buildEntries(t, chain, 10)

	// Remove entry at index 3 (sequence 4)
	entries = append(entries[:3], entries[4:]...)

	err := VerifyChain(entries, resolver)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrSequenceGap))
}

func TestChain_TamperPreviousHash(t *testing.T) {
	chain := NewChain("cage-1", "assess-1", "v1", testKeyV1)
	resolver := testResolver(map[string][]byte{"v1": testKeyV1})

	entries := buildEntries(t, chain, 10)

	entries[5].PreviousHash[0] ^= 0xff

	err := VerifyChain(entries, resolver)
	require.Error(t, err)
	// Could be either chain broken or signature mismatch depending on which
	// check fires first. PreviousHash is checked before signature.
	assert.True(t, errors.Is(err, ErrChainBroken))
}

func TestChain_KeyRotation(t *testing.T) {
	chain := NewChain("cage-1", "assess-1", "v1", testKeyV1)
	resolver := testResolver(map[string][]byte{"v1": testKeyV1, "v2": testKeyV2})

	entries := make([]Entry, 0, 10)
	for i := 0; i < 5; i++ {
		e, err := chain.Append(EntryTypeLLMRequest, []byte(fmt.Sprintf("req-%d", i)))
		require.NoError(t, err)
		entries = append(entries, e)
	}

	chain.RotateKey("v2", testKeyV2)

	for i := 5; i < 10; i++ {
		e, err := chain.Append(EntryTypeLLMResponse, []byte(fmt.Sprintf("resp-%d", i)))
		require.NoError(t, err)
		entries = append(entries, e)
	}

	require.NoError(t, VerifyChain(entries, resolver))

	assert.Equal(t, "v1", entries[0].KeyVersion)
	assert.Equal(t, "v2", entries[9].KeyVersion)
}

func TestChain_KeyRotationMissingKey(t *testing.T) {
	chain := NewChain("cage-1", "assess-1", "v1", testKeyV1)
	resolver := testResolver(map[string][]byte{"v1": testKeyV1})

	entries := make([]Entry, 0, 6)
	for i := 0; i < 3; i++ {
		e, err := chain.Append(EntryTypeLLMRequest, []byte(fmt.Sprintf("req-%d", i)))
		require.NoError(t, err)
		entries = append(entries, e)
	}

	chain.RotateKey("v2", testKeyV2)

	for i := 3; i < 6; i++ {
		e, err := chain.Append(EntryTypeLLMResponse, []byte(fmt.Sprintf("resp-%d", i)))
		require.NoError(t, err)
		entries = append(entries, e)
	}

	err := VerifyChain(entries, resolver)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown key version: v2")
}

func TestChain_Empty(t *testing.T) {
	resolver := testResolver(map[string][]byte{"v1": testKeyV1})
	err := VerifyChain(nil, resolver)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrEmptyChain))
}

func TestChain_SingleEntry(t *testing.T) {
	chain := NewChain("cage-1", "assess-1", "v1", testKeyV1)
	resolver := testResolver(map[string][]byte{"v1": testKeyV1})

	e, err := chain.Append(EntryTypeCageProvisioned, []byte("hello"))
	require.NoError(t, err)

	require.NoError(t, VerifyChain([]Entry{e}, resolver))
}

func TestChain_ConcurrentAppends(t *testing.T) {
	chain := NewChain("cage-1", "assess-1", "v1", testKeyV1)
	resolver := testResolver(map[string][]byte{"v1": testKeyV1})

	var mu sync.Mutex
	var allEntries []Entry
	var wg sync.WaitGroup

	for g := 0; g < 10; g++ {
		wg.Add(1)
		go func(goroutineID int) {
			defer wg.Done()
			for i := 0; i < 10; i++ {
				e, err := chain.Append(EntryTypeLLMRequest, []byte(fmt.Sprintf("g%d-i%d", goroutineID, i)))
				require.NoError(t, err)
				mu.Lock()
				allEntries = append(allEntries, e)
				mu.Unlock()
			}
		}(g)
	}

	wg.Wait()

	require.Len(t, allEntries, 100)
	assert.Equal(t, int64(100), chain.Sequence())

	sort.Slice(allEntries, func(i, j int) bool {
		return allEntries[i].Sequence < allEntries[j].Sequence
	})

	require.NoError(t, VerifyChain(allEntries, resolver))
}

func TestChain_HeadHash(t *testing.T) {
	chain := NewChain("cage-1", "assess-1", "v1", testKeyV1)

	genesis := chain.HeadHash()
	require.Len(t, genesis, 32)

	_, err := chain.Append(EntryTypeCageProvisioned, []byte("data"))
	require.NoError(t, err)

	afterFirst := chain.HeadHash()
	assert.NotEqual(t, genesis, afterFirst)

	// HeadHash returns a copy, not a reference
	afterFirst[0] ^= 0xff
	assert.NotEqual(t, afterFirst, chain.HeadHash())
}

func buildEntries(t *testing.T, chain *Chain, n int) []Entry {
	t.Helper()
	entries := make([]Entry, 0, n)
	for i := 0; i < n; i++ {
		e, err := chain.Append(EntryTypeLLMRequest, []byte(fmt.Sprintf("data-%d", i)))
		require.NoError(t, err)
		entries = append(entries, e)
	}
	return entries
}
