package audit

import (
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDigest_GenerateAndVerify(t *testing.T) {
	chain := NewChain("cage-1", "assess-1", "v1", testKeyV1)
	resolver := testResolver(map[string][]byte{"v1": testKeyV1})

	entries := buildEntries(t, chain, 5)
	headHash := ComputeHeadHash(entries)

	digest, err := GenerateDigest(entries, "assess-1", "cage-1", "v1", testKeyV1)
	require.NoError(t, err)

	assert.Equal(t, "assess-1", digest.AssessmentID)
	assert.Equal(t, "cage-1", digest.CageID)
	assert.Equal(t, int64(5), digest.EntryCount)
	assert.Equal(t, "v1", digest.KeyVersion)

	require.NoError(t, VerifyDigest(digest, headHash, resolver))
}

func TestDigest_TamperChainAfterDigest(t *testing.T) {
	chain := NewChain("cage-1", "assess-1", "v1", testKeyV1)
	resolver := testResolver(map[string][]byte{"v1": testKeyV1})

	entries := buildEntries(t, chain, 5)
	headHash := ComputeHeadHash(entries)

	digest, err := GenerateDigest(entries, "assess-1", "cage-1", "v1", testKeyV1)
	require.NoError(t, err)

	// Append more entries to change the chain head hash.
	extra, err := chain.Append(EntryTypeLLMRequest, []byte("extra"))
	require.NoError(t, err)
	entries = append(entries, extra)
	newHeadHash := ComputeHeadHash(entries)

	// Old digest should still verify against old head hash.
	require.NoError(t, VerifyDigest(digest, headHash, resolver))

	// Old digest must fail against new head hash.
	err = VerifyDigest(digest, newHeadHash, resolver)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "chain has been modified")
}

func TestDigest_TamperSignature(t *testing.T) {
	chain := NewChain("cage-1", "assess-1", "v1", testKeyV1)
	resolver := testResolver(map[string][]byte{"v1": testKeyV1})

	entries := buildEntries(t, chain, 5)
	headHash := ComputeHeadHash(entries)

	digest, err := GenerateDigest(entries, "assess-1", "cage-1", "v1", testKeyV1)
	require.NoError(t, err)

	digest.Signature[0] ^= 0xff

	err = VerifyDigest(digest, headHash, resolver)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "signature mismatch")
}

func TestDigest_TamperFields(t *testing.T) {
	chain := NewChain("cage-1", "assess-1", "v1", testKeyV1)
	resolver := testResolver(map[string][]byte{"v1": testKeyV1})

	entries := buildEntries(t, chain, 5)
	headHash := ComputeHeadHash(entries)

	digest, err := GenerateDigest(entries, "assess-1", "cage-1", "v1", testKeyV1)
	require.NoError(t, err)

	digest.EntryCount = 999

	err = VerifyDigest(digest, headHash, resolver)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "signature mismatch")
}

func TestDigest_EmptyChain(t *testing.T) {
	resolver := testResolver(map[string][]byte{"v1": testKeyV1})

	var entries []Entry
	headHash := ComputeHeadHash(entries)
	require.Equal(t, make([]byte, sha256.Size), headHash)

	digest, err := GenerateDigest(entries, "assess-1", "cage-1", "v1", testKeyV1)
	require.NoError(t, err)

	assert.Equal(t, int64(0), digest.EntryCount)

	require.NoError(t, VerifyDigest(digest, headHash, resolver))
}

func TestDigest_KeyRotation(t *testing.T) {
	chain := NewChain("cage-1", "assess-1", "v1", testKeyV1)
	resolver := testResolver(map[string][]byte{"v1": testKeyV1, "v2": testKeyV2})

	entries := buildEntries(t, chain, 5)
	headHash := ComputeHeadHash(entries)

	// Sign digest with v2 key.
	digest, err := GenerateDigest(entries, "assess-1", "cage-1", "v2", testKeyV2)
	require.NoError(t, err)

	assert.Equal(t, "v2", digest.KeyVersion)
	require.NoError(t, VerifyDigest(digest, headHash, resolver))
}

func TestComputeHeadHash_MatchesChainHeadHash(t *testing.T) {
	chain := NewChain("cage-1", "assess-1", "v1", testKeyV1)
	entries := buildEntries(t, chain, 5)

	fromChain := chain.HeadHash()
	fromEntries := ComputeHeadHash(entries)

	assert.Equal(t, fromChain, fromEntries)
}

func TestComputeHeadHash_Empty(t *testing.T) {
	h := ComputeHeadHash(nil)
	require.Len(t, h, sha256.Size)
	for _, b := range h {
		assert.Equal(t, byte(0), b)
	}
}

func TestDigest_MissingKeyVersion(t *testing.T) {
	chain := NewChain("cage-1", "assess-1", "v1", testKeyV1)
	resolver := testResolver(map[string][]byte{"v1": testKeyV1})

	entries := buildEntries(t, chain, 3)
	headHash := ComputeHeadHash(entries)

	digest, err := GenerateDigest(entries, "assess-1", "cage-1", "v3", []byte("v3-key"))
	require.NoError(t, err)

	err = VerifyDigest(digest, headHash, resolver)
	require.Error(t, err)
	assert.Contains(t, err.Error(), fmt.Sprintf("unknown key version: %s", "v3"))
}
