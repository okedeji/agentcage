package findings

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	_ "github.com/lib/pq"
)

// PGFindingStore implements FindingStore backed by Postgres.
type PGFindingStore struct {
	db *sql.DB
}

func NewPGFindingStore(db *sql.DB) *PGFindingStore {
	return &PGFindingStore{db: db}
}

func (s *PGFindingStore) SaveFinding(ctx context.Context, finding Finding) error {
	evidence, err := json.Marshal(finding.Evidence)
	if err != nil {
		return fmt.Errorf("marshaling evidence for finding %s: %w", finding.ID, err)
	}

	var parentID *string
	if finding.ParentFindingID != "" {
		parentID = &finding.ParentFindingID
	}

	_, err = s.db.ExecContext(ctx,
		`INSERT INTO findings (id, assessment_id, cage_id, status, severity, title, description, vuln_class, endpoint, evidence, parent_finding_id, chain_depth, validated_at, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
		 ON CONFLICT (id) DO NOTHING`,
		finding.ID,
		finding.AssessmentID,
		finding.CageID,
		finding.Status.String(),
		finding.Severity.String(),
		finding.Title,
		finding.Description,
		finding.VulnClass,
		finding.Endpoint,
		evidence,
		parentID,
		finding.ChainDepth,
		finding.ValidatedAt,
		finding.CreatedAt,
		finding.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("inserting finding %s for assessment %s: %w", finding.ID, finding.AssessmentID, err)
	}
	return nil
}

func (s *PGFindingStore) FindingExists(ctx context.Context, findingID string) (bool, error) {
	var exists bool
	err := s.db.QueryRowContext(ctx,
		`SELECT EXISTS(SELECT 1 FROM findings WHERE id = $1)`,
		findingID,
	).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("checking existence of finding %s: %w", findingID, err)
	}
	return exists, nil
}
