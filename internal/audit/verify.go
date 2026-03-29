package audit

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
)

var (
	ErrChainBroken       = errors.New("audit chain integrity violation")
	ErrSignatureMismatch = errors.New("entry signature mismatch")
	ErrSequenceGap       = errors.New("entry sequence gap")
	ErrEmptyChain        = errors.New("empty chain")
)

func VerifyChain(entries []Entry, resolve KeyResolver) error {
	if len(entries) == 0 {
		return ErrEmptyChain
	}

	previousHash := make([]byte, sha256.Size)

	for i, entry := range entries {
		expectedSeq := int64(i + 1)
		if entry.Sequence != expectedSeq {
			return fmt.Errorf("%w: expected sequence %d, got %d at position %d",
				ErrSequenceGap, expectedSeq, entry.Sequence, i)
		}

		if !hmac.Equal(entry.PreviousHash, previousHash) {
			return fmt.Errorf("%w: entry %d (cage %s) previous hash does not match",
				ErrChainBroken, entry.Sequence, entry.CageID)
		}

		key, err := resolve(entry.KeyVersion)
		if err != nil {
			return fmt.Errorf("resolving key version %s for entry %d: %w",
				entry.KeyVersion, entry.Sequence, err)
		}

		expectedSig, err := signEntry(entry, key)
		if err != nil {
			return fmt.Errorf("computing signature for entry %d: %w", entry.Sequence, err)
		}

		if !hmac.Equal(entry.Signature, expectedSig) {
			return fmt.Errorf("%w: entry %d (cage %s) has been tampered with",
				ErrSignatureMismatch, entry.Sequence, entry.CageID)
		}

		previousHash = hashEntry(entry)
	}

	return nil
}
