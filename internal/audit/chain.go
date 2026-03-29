package audit

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Chain maintains the state needed to append new entries to a
// tamper-evident audit log. It is safe for concurrent use.
type Chain struct {
	mu           sync.Mutex
	cageID       string
	assessmentID string
	sequence     int64
	lastHash     []byte
	keyVersion   string
	key          []byte
}

func NewChain(cageID, assessmentID, keyVersion string, key []byte) *Chain {
	return &Chain{
		cageID:       cageID,
		assessmentID: assessmentID,
		sequence:     0,
		lastHash:     make([]byte, sha256.Size),
		keyVersion:   keyVersion,
		key:          key,
	}
}

func (c *Chain) Append(entryType EntryType, data []byte) (Entry, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.sequence++

	entry := Entry{
		ID:           uuid.NewString(),
		CageID:       c.cageID,
		AssessmentID: c.assessmentID,
		Sequence:     c.sequence,
		Type:         entryType,
		Timestamp:    time.Now(),
		Data:         data,
		KeyVersion:   c.keyVersion,
		PreviousHash: make([]byte, len(c.lastHash)),
	}
	copy(entry.PreviousHash, c.lastHash)

	sig, err := signEntry(entry, c.key)
	if err != nil {
		c.sequence--
		return Entry{}, fmt.Errorf("signing entry %d for cage %s: %w", c.sequence+1, c.cageID, err)
	}
	entry.Signature = sig

	c.lastHash = hashEntry(entry)

	return entry, nil
}

func (c *Chain) HeadHash() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	result := make([]byte, len(c.lastHash))
	copy(result, c.lastHash)
	return result
}

func (c *Chain) Sequence() int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.sequence
}

func (c *Chain) RotateKey(newVersion string, newKey []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.keyVersion = newVersion
	c.key = newKey
}

// signEntry computes HMAC-SHA256 over a canonical JSON representation of the
// entry's content fields. The signature covers every field except the signature
// itself, so tampering with any field invalidates the signature.
func signEntry(e Entry, key []byte) ([]byte, error) {
	payload := struct {
		CageID       string `json:"cage_id"`
		AssessmentID string `json:"assessment_id"`
		Sequence     int64  `json:"sequence"`
		Type         string `json:"type"`
		Timestamp    string `json:"timestamp"`
		Data         []byte `json:"data"`
		PreviousHash []byte `json:"previous_hash"`
	}{
		CageID:       e.CageID,
		AssessmentID: e.AssessmentID,
		Sequence:     e.Sequence,
		Type:         e.Type.String(),
		Timestamp:    e.Timestamp.UTC().Format(time.RFC3339Nano),
		Data:         e.Data,
		PreviousHash: e.PreviousHash,
	}

	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshaling sign payload: %w", err)
	}

	mac := hmac.New(sha256.New, key)
	mac.Write(raw)
	return mac.Sum(nil), nil
}

// hashEntry produces the chain link value: the SHA-256 of the entry's signature.
// Each subsequent entry stores this as its PreviousHash field.
func hashEntry(e Entry) []byte {
	h := sha256.Sum256(e.Signature)
	return h[:]
}
