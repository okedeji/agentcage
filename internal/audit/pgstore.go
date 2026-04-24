package audit

import (
	"context"
	"database/sql"
	"fmt"

	_ "github.com/lib/pq"
)

type PGStore struct {
	db *sql.DB
}

func NewPGStore(db *sql.DB) *PGStore {
	return &PGStore{db: db}
}

func (s *PGStore) AppendEntry(ctx context.Context, entry Entry) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO audit_entries (id, cage_id, assessment_id, sequence, entry_type, timestamp, data, key_version, signature, previous_hash)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		 ON CONFLICT (cage_id, sequence) DO NOTHING`,
		entry.ID,
		entry.CageID,
		entry.AssessmentID,
		entry.Sequence,
		entry.Type.String(),
		entry.Timestamp,
		entry.Data,
		entry.KeyVersion,
		entry.Signature,
		entry.PreviousHash,
	)
	if err != nil {
		return fmt.Errorf("appending audit entry %s for cage %s: %w", entry.ID, entry.CageID, err)
	}
	return nil
}

func (s *PGStore) GetEntries(ctx context.Context, cageID string) ([]Entry, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, cage_id, assessment_id, sequence, entry_type, timestamp, data, key_version, signature, previous_hash
		 FROM audit_entries
		 WHERE cage_id = $1
		 ORDER BY sequence ASC`,
		cageID,
	)
	if err != nil {
		return nil, fmt.Errorf("querying audit entries for cage %s: %w", cageID, err)
	}
	defer func() { _ = rows.Close() }()

	var entries []Entry
	for rows.Next() {
		var e Entry
		var typeName string
		var data []byte
		if err := rows.Scan(
			&e.ID,
			&e.CageID,
			&e.AssessmentID,
			&e.Sequence,
			&typeName,
			&e.Timestamp,
			&data,
			&e.KeyVersion,
			&e.Signature,
			&e.PreviousHash,
		); err != nil {
			return nil, fmt.Errorf("scanning audit entry for cage %s: %w", cageID, err)
		}
		e.Type = entryTypeFromString(typeName)
		e.Data = data
		entries = append(entries, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating audit entries for cage %s: %w", cageID, err)
	}
	return entries, nil
}

func (s *PGStore) SaveDigest(ctx context.Context, digest Digest) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO audit_digests (assessment_id, cage_id, chain_head_hash, entry_count, key_version, signature, issued_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)
		 ON CONFLICT (cage_id, issued_at) DO NOTHING`,
		digest.AssessmentID,
		digest.CageID,
		digest.ChainHeadHash,
		digest.EntryCount,
		digest.KeyVersion,
		digest.Signature,
		digest.IssuedAt,
	)
	if err != nil {
		return fmt.Errorf("saving digest for cage %s: %w", digest.CageID, err)
	}
	return nil
}

func (s *PGStore) GetDigest(ctx context.Context, cageID string) (*Digest, error) {
	var d Digest
	err := s.db.QueryRowContext(ctx,
		`SELECT assessment_id, cage_id, chain_head_hash, entry_count, key_version, signature, issued_at
		 FROM audit_digests
		 WHERE cage_id = $1
		 ORDER BY issued_at DESC
		 LIMIT 1`,
		cageID,
	).Scan(
		&d.AssessmentID,
		&d.CageID,
		&d.ChainHeadHash,
		&d.EntryCount,
		&d.KeyVersion,
		&d.Signature,
		&d.IssuedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("querying digest for cage %s: %w", cageID, err)
	}
	return &d, nil
}

func (s *PGStore) GetLatestDigest(ctx context.Context, assessmentID string) (*Digest, error) {
	var d Digest
	err := s.db.QueryRowContext(ctx,
		`SELECT assessment_id, cage_id, chain_head_hash, entry_count, key_version, signature, issued_at
		 FROM audit_digests
		 WHERE assessment_id = $1
		 ORDER BY issued_at DESC
		 LIMIT 1`,
		assessmentID,
	).Scan(
		&d.AssessmentID,
		&d.CageID,
		&d.ChainHeadHash,
		&d.EntryCount,
		&d.KeyVersion,
		&d.Signature,
		&d.IssuedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("querying latest digest for assessment %s: %w", assessmentID, err)
	}
	return &d, nil
}

func (s *PGStore) GetEntriesFiltered(ctx context.Context, cageID, typeFilter string, limit int) ([]Entry, error) {
	query := `SELECT id, cage_id, assessment_id, sequence, entry_type, timestamp, data, key_version, signature, previous_hash
		 FROM audit_entries
		 WHERE cage_id = $1`
	args := []any{cageID}
	argIdx := 2

	if typeFilter != "" {
		query += fmt.Sprintf(` AND entry_type = $%d`, argIdx)
		args = append(args, typeFilter)
		argIdx++
	}

	query += ` ORDER BY sequence ASC`

	if limit > 0 {
		query += fmt.Sprintf(` LIMIT $%d`, argIdx)
		args = append(args, limit)
	}

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("querying filtered audit entries for cage %s: %w", cageID, err)
	}
	defer func() { _ = rows.Close() }()

	var entries []Entry
	for rows.Next() {
		var e Entry
		var typeName string
		var data []byte
		if err := rows.Scan(&e.ID, &e.CageID, &e.AssessmentID, &e.Sequence, &typeName, &e.Timestamp, &data, &e.KeyVersion, &e.Signature, &e.PreviousHash); err != nil {
			return nil, fmt.Errorf("scanning audit entry: %w", err)
		}
		e.Type = entryTypeFromString(typeName)
		e.Data = data
		entries = append(entries, e)
	}
	return entries, rows.Err()
}

func (s *PGStore) GetEntryByID(ctx context.Context, entryID string) (*Entry, error) {
	var e Entry
	var typeName string
	var data []byte
	err := s.db.QueryRowContext(ctx,
		`SELECT id, cage_id, assessment_id, sequence, entry_type, timestamp, data, key_version, signature, previous_hash
		 FROM audit_entries WHERE id = $1`,
		entryID,
	).Scan(&e.ID, &e.CageID, &e.AssessmentID, &e.Sequence, &typeName, &e.Timestamp, &data, &e.KeyVersion, &e.Signature, &e.PreviousHash)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("querying audit entry %s: %w", entryID, err)
	}
	e.Type = entryTypeFromString(typeName)
	e.Data = data
	return &e, nil
}

func (s *PGStore) GetEntriesByAssessment(ctx context.Context, assessmentID string) ([]Entry, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, cage_id, assessment_id, sequence, entry_type, timestamp, data, key_version, signature, previous_hash
		 FROM audit_entries
		 WHERE assessment_id = $1
		 ORDER BY cage_id, sequence ASC`,
		assessmentID,
	)
	if err != nil {
		return nil, fmt.Errorf("querying audit entries for assessment %s: %w", assessmentID, err)
	}
	defer func() { _ = rows.Close() }()

	var entries []Entry
	for rows.Next() {
		var e Entry
		var typeName string
		var data []byte
		if err := rows.Scan(&e.ID, &e.CageID, &e.AssessmentID, &e.Sequence, &typeName, &e.Timestamp, &data, &e.KeyVersion, &e.Signature, &e.PreviousHash); err != nil {
			return nil, fmt.Errorf("scanning audit entry for assessment %s: %w", assessmentID, err)
		}
		e.Type = entryTypeFromString(typeName)
		e.Data = data
		entries = append(entries, e)
	}
	return entries, rows.Err()
}

func (s *PGStore) ListCagesWithAudit(ctx context.Context, assessmentID string) ([]string, error) {
	query := `SELECT DISTINCT cage_id FROM audit_entries`
	var args []any
	if assessmentID != "" {
		query += ` WHERE assessment_id = $1`
		args = append(args, assessmentID)
	}
	query += ` ORDER BY cage_id`

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("listing cages with audit entries: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scanning cage id: %w", err)
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

func (s *PGStore) GetKeyVersions(ctx context.Context, cageID string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT DISTINCT key_version FROM audit_entries WHERE cage_id = $1 ORDER BY key_version`,
		cageID,
	)
	if err != nil {
		return nil, fmt.Errorf("querying key versions for cage %s: %w", cageID, err)
	}
	defer func() { _ = rows.Close() }()

	var versions []string
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return nil, fmt.Errorf("scanning key version: %w", err)
		}
		versions = append(versions, v)
	}
	return versions, rows.Err()
}

func entryTypeFromString(s string) EntryType {
	for et, name := range entryTypeNames {
		if name == s {
			return et
		}
	}
	return EntryTypeUnspecified
}
