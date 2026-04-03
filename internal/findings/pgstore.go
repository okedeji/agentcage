package findings

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

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

func (s *PGFindingStore) GetByAssessment(ctx context.Context, assessmentID string, status Status) ([]Finding, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, assessment_id, cage_id, status, severity, title, description, vuln_class, endpoint, evidence, parent_finding_id, chain_depth, validated_at, created_at, updated_at
		 FROM findings
		 WHERE assessment_id = $1 AND status = $2
		 ORDER BY created_at`,
		assessmentID, status.String(),
	)
	if err != nil {
		return nil, fmt.Errorf("querying findings for assessment %s with status %s: %w", assessmentID, status, err)
	}
	defer func() { _ = rows.Close() }()

	var results []Finding
	for rows.Next() {
		var f Finding
		var statusStr, severityStr string
		var evidence []byte
		var parentID *string
		var validatedAt *time.Time

		if err := rows.Scan(
			&f.ID, &f.AssessmentID, &f.CageID,
			&statusStr, &severityStr,
			&f.Title, &f.Description, &f.VulnClass, &f.Endpoint,
			&evidence, &parentID, &f.ChainDepth, &validatedAt,
			&f.CreatedAt, &f.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("scanning finding row: %w", err)
		}

		f.Status = parseStatus(statusStr)
		f.Severity = parseSeverity(severityStr)
		f.ValidatedAt = validatedAt
		if parentID != nil {
			f.ParentFindingID = *parentID
		}
		if evidence != nil {
			_ = json.Unmarshal(evidence, &f.Evidence)
		}
		results = append(results, f)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating findings for assessment %s: %w", assessmentID, err)
	}
	return results, nil
}

func (s *PGFindingStore) UpdateStatus(ctx context.Context, findingID string, status Status) error {
	var validatedAt interface{}
	if status == StatusValidated {
		now := time.Now()
		validatedAt = now
	}

	_, err := s.db.ExecContext(ctx,
		`UPDATE findings SET status = $1, validated_at = COALESCE($2, validated_at), updated_at = NOW() WHERE id = $3`,
		status.String(), validatedAt, findingID,
	)
	if err != nil {
		return fmt.Errorf("updating status of finding %s to %s: %w", findingID, status, err)
	}
	return nil
}

func parseStatus(s string) Status {
	switch s {
	case "candidate":
		return StatusCandidate
	case "validated":
		return StatusValidated
	case "rejected":
		return StatusRejected
	default:
		return StatusCandidate
	}
}

func parseSeverity(s string) Severity {
	switch s {
	case "info":
		return SeverityInfo
	case "low":
		return SeverityLow
	case "medium":
		return SeverityMedium
	case "high":
		return SeverityHigh
	case "critical":
		return SeverityCritical
	default:
		return SeverityInfo
	}
}
