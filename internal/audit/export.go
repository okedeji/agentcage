package audit

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

type ExportEnvelope struct {
	CageID       string        `json:"cage_id"`
	AssessmentID string        `json:"assessment_id"`
	Entries      []exportEntry `json:"entries"`
	Digest       *Digest       `json:"digest,omitempty"`
	ExportedAt   time.Time     `json:"exported_at"`
}

type exportEntry struct {
	ID           string          `json:"id"`
	Sequence     int64           `json:"sequence"`
	Type         string          `json:"type"`
	Timestamp    string          `json:"timestamp"`
	Data         json.RawMessage `json:"data"`
	KeyVersion   string          `json:"key_version"`
	Signature    []byte          `json:"signature"`
	PreviousHash []byte          `json:"previous_hash"`
}

func Export(entries []Entry, digest *Digest) ([]byte, error) {
	if len(entries) == 0 {
		return nil, errors.New("exporting audit log: entries must not be empty")
	}

	envelope := buildEnvelope(entries, digest)

	raw, err := json.MarshalIndent(envelope, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshaling export envelope for cage %s: %w", entries[0].CageID, err)
	}

	return raw, nil
}

func ExportPartial(entries []Entry) ([]byte, error) {
	envelope := buildEnvelope(entries, nil)

	var cageID string
	if len(entries) > 0 {
		cageID = entries[0].CageID
	}

	raw, err := json.MarshalIndent(envelope, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshaling partial export envelope for cage %s: %w", cageID, err)
	}

	return raw, nil
}

func buildEnvelope(entries []Entry, digest *Digest) ExportEnvelope {
	exported := make([]exportEntry, len(entries))
	for i, e := range entries {
		exported[i] = exportEntry{
			ID:           e.ID,
			Sequence:     e.Sequence,
			Type:         e.Type.String(),
			Timestamp:    e.Timestamp.UTC().Format(time.RFC3339Nano),
			Data:         json.RawMessage(e.Data),
			KeyVersion:   e.KeyVersion,
			Signature:    e.Signature,
			PreviousHash: e.PreviousHash,
		}
	}

	var cageID, assessmentID string
	if len(entries) > 0 {
		cageID = entries[0].CageID
		assessmentID = entries[0].AssessmentID
	}

	return ExportEnvelope{
		CageID:       cageID,
		AssessmentID: assessmentID,
		Entries:      exported,
		Digest:       digest,
		ExportedAt:   time.Now().UTC(),
	}
}
