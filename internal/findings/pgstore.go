package findings

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	_ "github.com/lib/pq"
)

// PGStore is the Postgres-backed FindingStore.
type PGStore struct {
	db *sql.DB
}

func NewPGStore(db *sql.DB) *PGStore {
	return &PGStore{db: db}
}

func (s *PGStore) SaveFinding(ctx context.Context, finding Finding) error {
	evidence, err := json.Marshal(finding.Evidence)
	if err != nil {
		return fmt.Errorf("marshaling evidence for finding %s: %w", finding.ID, err)
	}

	var parentID *string
	if finding.ParentFindingID != "" {
		parentID = &finding.ParentFindingID
	}

	var validationProof []byte
	if finding.ValidationProof != nil {
		validationProof, err = json.Marshal(finding.ValidationProof)
		if err != nil {
			return fmt.Errorf("marshaling validation proof for finding %s: %w", finding.ID, err)
		}
	}

	_, err = s.db.ExecContext(ctx,
		`INSERT INTO findings (id, assessment_id, cage_id, status, severity, title, description, vuln_class, endpoint, evidence, parent_finding_id, chain_depth, cwe, cvss_score, remediation, validation_proof, validated_at, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19)
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
		finding.CWE,
		finding.CVSSScore,
		finding.Remediation,
		validationProof,
		finding.ValidatedAt,
		finding.CreatedAt,
		finding.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("inserting finding %s for assessment %s: %w", finding.ID, finding.AssessmentID, err)
	}
	return nil
}

func (s *PGStore) FindingExists(ctx context.Context, findingID string) (bool, error) {
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

func (s *PGStore) GetByID(ctx context.Context, findingID string) (Finding, error) {
	var (
		f                       Finding
		statusStr, severityStr  string
		description, endpoint   *string
		cwe, remediation        *string
		cvssScore               *float64
		evidence                []byte
		validationProofJSON     []byte
		parentID                *string
		validatedAt             *time.Time
	)
	err := s.db.QueryRowContext(ctx,
		`SELECT id, assessment_id, cage_id, status, severity, title, description, vuln_class, endpoint, evidence, parent_finding_id, chain_depth, cwe, cvss_score, remediation, validation_proof, validated_at, created_at, updated_at
		 FROM findings WHERE id = $1`,
		findingID,
	).Scan(
		&f.ID, &f.AssessmentID, &f.CageID,
		&statusStr, &severityStr,
		&f.Title, &description, &f.VulnClass, &endpoint,
		&evidence, &parentID, &f.ChainDepth,
		&cwe, &cvssScore, &remediation, &validationProofJSON,
		&validatedAt, &f.CreatedAt, &f.UpdatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return Finding{}, fmt.Errorf("%w: %s", ErrFindingNotFound, findingID)
	}
	if err != nil {
		return Finding{}, fmt.Errorf("loading finding %s: %w", findingID, err)
	}
	f.Status = parseStatus(statusStr)
	f.Severity = parseSeverity(severityStr)
	f.ValidatedAt = validatedAt
	if description != nil {
		f.Description = *description
	}
	if endpoint != nil {
		f.Endpoint = *endpoint
	}
	if cwe != nil {
		f.CWE = *cwe
	}
	if cvssScore != nil {
		f.CVSSScore = *cvssScore
	}
	if remediation != nil {
		f.Remediation = *remediation
	}
	if parentID != nil {
		f.ParentFindingID = *parentID
	}
	if evidence != nil {
		if err := json.Unmarshal(evidence, &f.Evidence); err != nil {
			return Finding{}, fmt.Errorf("unmarshaling evidence for finding %s: %w", findingID, err)
		}
	}
	if validationProofJSON != nil {
		var proof Proof
		if err := json.Unmarshal(validationProofJSON, &proof); err != nil {
			return Finding{}, fmt.Errorf("unmarshaling validation proof for finding %s: %w", findingID, err)
		}
		f.ValidationProof = &proof
	}
	return f, nil
}

func (s *PGStore) GetByAssessment(ctx context.Context, assessmentID string, status Status) ([]Finding, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, assessment_id, cage_id, status, severity, title, description, vuln_class, endpoint, evidence, parent_finding_id, chain_depth, cwe, cvss_score, remediation, validation_proof, validated_at, created_at, updated_at
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
		var description, endpoint *string
		var cwe, remediation *string
		var cvssScore *float64
		var evidence []byte
		var validationProofJSON []byte
		var parentID *string
		var validatedAt *time.Time

		if err := rows.Scan(
			&f.ID, &f.AssessmentID, &f.CageID,
			&statusStr, &severityStr,
			&f.Title, &description, &f.VulnClass, &endpoint,
			&evidence, &parentID, &f.ChainDepth,
			&cwe, &cvssScore, &remediation, &validationProofJSON,
			&validatedAt, &f.CreatedAt, &f.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("scanning finding row: %w", err)
		}

		f.Status = parseStatus(statusStr)
		f.Severity = parseSeverity(severityStr)
		f.ValidatedAt = validatedAt
		if description != nil {
			f.Description = *description
		}
		if endpoint != nil {
			f.Endpoint = *endpoint
		}
		if cwe != nil {
			f.CWE = *cwe
		}
		if cvssScore != nil {
			f.CVSSScore = *cvssScore
		}
		if remediation != nil {
			f.Remediation = *remediation
		}
		if parentID != nil {
			f.ParentFindingID = *parentID
		}
		if evidence != nil {
			if err := json.Unmarshal(evidence, &f.Evidence); err != nil {
				return nil, fmt.Errorf("unmarshaling evidence for finding %s: %w", f.ID, err)
			}
		}
		if validationProofJSON != nil {
			var proof Proof
			if err := json.Unmarshal(validationProofJSON, &proof); err != nil {
				return nil, fmt.Errorf("unmarshaling validation proof for finding %s: %w", f.ID, err)
			}
			f.ValidationProof = &proof
		}
		results = append(results, f)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating findings for assessment %s: %w", assessmentID, err)
	}
	return results, nil
}

type ListFilters struct {
	AssessmentID   string
	StatusFilter   *Status
	SeverityFilter *Severity
	Limit          int
}

func (s *PGStore) ListFindings(ctx context.Context, filters ListFilters) ([]Finding, error) {
	limit := filters.Limit
	if limit <= 0 || limit > 500 {
		limit = 100
	}

	query := `SELECT id, assessment_id, cage_id, status, severity, title, vuln_class, endpoint, parent_finding_id, chain_depth, cwe, cvss_score, validated_at, created_at
		 FROM findings`
	var whereClauses []string
	var args []any
	argIdx := 1

	if filters.AssessmentID != "" {
		whereClauses = append(whereClauses, fmt.Sprintf(`assessment_id = $%d`, argIdx))
		args = append(args, filters.AssessmentID)
		argIdx++
	}
	if filters.StatusFilter != nil {
		whereClauses = append(whereClauses, fmt.Sprintf(`status = $%d`, argIdx))
		args = append(args, filters.StatusFilter.String())
		argIdx++
	}
	if filters.SeverityFilter != nil {
		whereClauses = append(whereClauses, fmt.Sprintf(`severity = $%d`, argIdx))
		args = append(args, filters.SeverityFilter.String())
		argIdx++
	}

	if len(whereClauses) > 0 {
		query += ` WHERE ` + strings.Join(whereClauses, ` AND `)
	}

	query += ` ORDER BY created_at DESC`
	query += fmt.Sprintf(` LIMIT $%d`, argIdx)
	args = append(args, limit)

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("listing findings: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var results []Finding
	for rows.Next() {
		var f Finding
		var statusStr, severityStr string
		var endpoint *string
		var cwe *string
		var cvssScore *float64
		var parentID *string
		var validatedAt *time.Time

		if err := rows.Scan(
			&f.ID, &f.AssessmentID, &f.CageID,
			&statusStr, &severityStr,
			&f.Title, &f.VulnClass, &endpoint,
			&parentID, &f.ChainDepth,
			&cwe, &cvssScore,
			&validatedAt, &f.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("scanning finding row: %w", err)
		}

		f.Status = parseStatus(statusStr)
		f.Severity = parseSeverity(severityStr)
		f.ValidatedAt = validatedAt
		if endpoint != nil {
			f.Endpoint = *endpoint
		}
		if cwe != nil {
			f.CWE = *cwe
		}
		if cvssScore != nil {
			f.CVSSScore = *cvssScore
		}
		if parentID != nil {
			f.ParentFindingID = *parentID
		}
		results = append(results, f)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating finding rows: %w", err)
	}
	return results, nil
}

type StatusCounts struct {
	Candidate int32
	Validated int32
	Rejected  int32
}

func (s *PGStore) CountByAssessment(ctx context.Context, assessmentID string) (StatusCounts, error) {
	var counts StatusCounts
	rows, err := s.db.QueryContext(ctx,
		`SELECT status, COUNT(*) FROM findings WHERE assessment_id = $1 GROUP BY status`,
		assessmentID,
	)
	if err != nil {
		return counts, fmt.Errorf("counting findings for assessment %s: %w", assessmentID, err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var statusStr string
		var count int32
		if err := rows.Scan(&statusStr, &count); err != nil {
			return counts, fmt.Errorf("scanning finding count row: %w", err)
		}
		switch statusStr {
		case "candidate":
			counts.Candidate = count
		case "validated":
			counts.Validated = count
		case "rejected":
			counts.Rejected = count
		}
	}
	return counts, rows.Err()
}

func (s *PGStore) UpdateEnrichment(ctx context.Context, findingID, cwe string, cvssScore float64, remediation string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE findings SET cwe = $1, cvss_score = $2, remediation = $3, updated_at = NOW() WHERE id = $4`,
		cwe, cvssScore, remediation, findingID,
	)
	if err != nil {
		return fmt.Errorf("updating enrichment for finding %s: %w", findingID, err)
	}
	return nil
}

func (s *PGStore) UpdateValidationProof(ctx context.Context, findingID string, proof *Proof) error {
	proofJSON, err := json.Marshal(proof)
	if err != nil {
		return fmt.Errorf("marshaling validation proof for finding %s: %w", findingID, err)
	}
	_, err = s.db.ExecContext(ctx,
		`UPDATE findings SET validation_proof = $1, updated_at = NOW() WHERE id = $2`,
		proofJSON, findingID,
	)
	if err != nil {
		return fmt.Errorf("updating validation proof for finding %s: %w", findingID, err)
	}
	return nil
}

func (s *PGStore) DeleteFinding(ctx context.Context, findingID string) error {
	result, err := s.db.ExecContext(ctx, `DELETE FROM findings WHERE id = $1`, findingID)
	if err != nil {
		return fmt.Errorf("deleting finding %s: %w", findingID, err)
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		return fmt.Errorf("%w: %s", ErrFindingNotFound, findingID)
	}
	return nil
}

func (s *PGStore) DeleteByAssessment(ctx context.Context, assessmentID string) (int64, error) {
	result, err := s.db.ExecContext(ctx, `DELETE FROM findings WHERE assessment_id = $1`, assessmentID)
	if err != nil {
		return 0, fmt.Errorf("deleting findings for assessment %s: %w", assessmentID, err)
	}
	n, _ := result.RowsAffected()
	return n, nil
}

func (s *PGStore) UpdateStatus(ctx context.Context, findingID string, status Status) error {
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
	if v := ParseStatus(s); v != 0 {
		return v
	}
	return StatusCandidate
}

func parseSeverity(s string) Severity {
	if v := ParseSeverity(s); v != 0 {
		return v
	}
	return SeverityInfo
}
