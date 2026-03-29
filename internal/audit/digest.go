package audit

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"time"
)

func ComputeHeadHash(entries []Entry) []byte {
	if len(entries) == 0 {
		return make([]byte, sha256.Size)
	}
	return hashEntry(entries[len(entries)-1])
}

func GenerateDigest(entries []Entry, assessmentID, cageID, keyVersion string, key []byte) (Digest, error) {
	headHash := ComputeHeadHash(entries)
	now := time.Now().UTC()

	sig, err := signDigest(assessmentID, cageID, headHash, int64(len(entries)), now, key)
	if err != nil {
		return Digest{}, fmt.Errorf("generating digest for cage %s: %w", cageID, err)
	}

	return Digest{
		AssessmentID:  assessmentID,
		CageID:        cageID,
		ChainHeadHash: headHash,
		EntryCount:    int64(len(entries)),
		KeyVersion:    keyVersion,
		Signature:     sig,
		IssuedAt:      now,
	}, nil
}

func VerifyDigest(digest Digest, currentHeadHash []byte, resolve KeyResolver) error {
	key, err := resolve(digest.KeyVersion)
	if err != nil {
		return fmt.Errorf("resolving key version %s for digest: %w", digest.KeyVersion, err)
	}

	if !hmac.Equal(digest.ChainHeadHash, currentHeadHash) {
		return fmt.Errorf("chain has been modified since digest was issued for cage %s", digest.CageID)
	}

	expectedSig, err := signDigest(
		digest.AssessmentID,
		digest.CageID,
		digest.ChainHeadHash,
		digest.EntryCount,
		digest.IssuedAt,
		key,
	)
	if err != nil {
		return fmt.Errorf("recomputing digest signature for cage %s: %w", digest.CageID, err)
	}

	if !hmac.Equal(digest.Signature, expectedSig) {
		return fmt.Errorf("digest signature mismatch for cage %s: digest has been tampered with", digest.CageID)
	}

	return nil
}

func signDigest(assessmentID, cageID string, chainHeadHash []byte, entryCount int64, issuedAt time.Time, key []byte) ([]byte, error) {
	payload := struct {
		AssessmentID  string `json:"assessment_id"`
		CageID        string `json:"cage_id"`
		ChainHeadHash []byte `json:"chain_head_hash"`
		EntryCount    int64  `json:"entry_count"`
		IssuedAt      string `json:"issued_at"`
	}{
		AssessmentID:  assessmentID,
		CageID:        cageID,
		ChainHeadHash: chainHeadHash,
		EntryCount:    entryCount,
		IssuedAt:      issuedAt.UTC().Format(time.RFC3339Nano),
	}

	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshaling digest sign payload: %w", err)
	}

	mac := hmac.New(sha256.New, key)
	mac.Write(raw)
	return mac.Sum(nil), nil
}
