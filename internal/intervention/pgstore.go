package intervention

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	_ "github.com/lib/pq"
)

// PGStore implements Store backed by Postgres.
type PGStore struct {
	db *sql.DB
}

func NewPGStore(db *sql.DB) *PGStore {
	return &PGStore{db: db}
}

func (s *PGStore) SaveIntervention(ctx context.Context, req Request) error {
	var timeoutAt *time.Time
	if req.Timeout > 0 {
		t := req.CreatedAt.Add(req.Timeout)
		timeoutAt = &t
	}

	_, err := s.db.ExecContext(ctx,
		`INSERT INTO interventions (id, type, status, priority, cage_id, assessment_id, description, context_data, timeout_at, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		 ON CONFLICT (id) DO NOTHING`,
		req.ID,
		typeToString(req.Type),
		statusToString(req.Status),
		priorityToString(req.Priority),
		nullIfEmpty(req.CageID),
		req.AssessmentID,
		req.Description,
		req.ContextData,
		timeoutAt,
		req.CreatedAt,
		req.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("inserting intervention %s for assessment %s: %w", req.ID, req.AssessmentID, err)
	}
	return nil
}

func (s *PGStore) UpdateIntervention(ctx context.Context, req Request) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE interventions
		 SET status = $2, resolved_at = $3, updated_at = NOW()
		 WHERE id = $1`,
		req.ID,
		statusToString(req.Status),
		req.ResolvedAt,
	)
	if err != nil {
		return fmt.Errorf("updating intervention %s: %w", req.ID, err)
	}
	return nil
}

func (s *PGStore) GetIntervention(ctx context.Context, id string) (*Request, error) {
	var (
		req        Request
		typeName   string
		statusName string
		priorityName string
		cageID     sql.NullString
		timeoutAt  sql.NullTime
		resolvedAt sql.NullTime
	)

	err := s.db.QueryRowContext(ctx,
		`SELECT id, type, status, priority, cage_id, assessment_id, description, context_data, timeout_at, created_at, resolved_at
		 FROM interventions
		 WHERE id = $1`,
		id,
	).Scan(
		&req.ID,
		&typeName,
		&statusName,
		&priorityName,
		&cageID,
		&req.AssessmentID,
		&req.Description,
		&req.ContextData,
		&timeoutAt,
		&req.CreatedAt,
		&resolvedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("querying intervention %s: %w", id, err)
	}

	req.Type = typeFromString(typeName)
	req.Status = statusFromString(statusName)
	req.Priority = priorityFromString(priorityName)
	if cageID.Valid {
		req.CageID = cageID.String
	}
	if timeoutAt.Valid {
		req.Timeout = timeoutAt.Time.Sub(req.CreatedAt)
	}
	if resolvedAt.Valid {
		req.ResolvedAt = &resolvedAt.Time
	}

	return &req, nil
}

func (s *PGStore) ListInterventions(ctx context.Context, filters ListFilters) ([]Request, string, error) {
	query := `SELECT id, type, status, priority, cage_id, assessment_id, description, context_data, timeout_at, created_at, resolved_at
		 FROM interventions WHERE 1=1`
	args := []any{}
	argIdx := 1

	if filters.StatusFilter != nil {
		query += fmt.Sprintf(" AND status = $%d", argIdx)
		args = append(args, statusToString(*filters.StatusFilter))
		argIdx++
	}
	if filters.TypeFilter != nil {
		query += fmt.Sprintf(" AND type = $%d", argIdx)
		args = append(args, typeToString(*filters.TypeFilter))
		argIdx++
	}
	if filters.AssessmentID != "" {
		query += fmt.Sprintf(" AND assessment_id = $%d", argIdx)
		args = append(args, filters.AssessmentID)
		argIdx++
	}
	if filters.PageToken != "" {
		query += fmt.Sprintf(" AND id > $%d", argIdx)
		args = append(args, filters.PageToken)
		argIdx++
	}

	query += " ORDER BY priority DESC, created_at ASC"

	pageSize := filters.PageSize
	if pageSize <= 0 {
		pageSize = 50
	}
	query += fmt.Sprintf(" LIMIT $%d", argIdx)
	args = append(args, pageSize+1)

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, "", fmt.Errorf("listing interventions: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var results []Request
	for rows.Next() {
		var (
			req          Request
			typeName     string
			statusName   string
			priorityName string
			cageID       sql.NullString
			timeoutAt    sql.NullTime
			resolvedAt   sql.NullTime
		)
		if err := rows.Scan(
			&req.ID,
			&typeName,
			&statusName,
			&priorityName,
			&cageID,
			&req.AssessmentID,
			&req.Description,
			&req.ContextData,
			&timeoutAt,
			&req.CreatedAt,
			&resolvedAt,
		); err != nil {
			return nil, "", fmt.Errorf("scanning intervention row: %w", err)
		}
		req.Type = typeFromString(typeName)
		req.Status = statusFromString(statusName)
		req.Priority = priorityFromString(priorityName)
		if cageID.Valid {
			req.CageID = cageID.String
		}
		if timeoutAt.Valid {
			req.Timeout = timeoutAt.Time.Sub(req.CreatedAt)
		}
		if resolvedAt.Valid {
			req.ResolvedAt = &resolvedAt.Time
		}
		results = append(results, req)
	}
	if err := rows.Err(); err != nil {
		return nil, "", fmt.Errorf("iterating intervention rows: %w", err)
	}

	var nextToken string
	if len(results) > pageSize {
		nextToken = results[pageSize-1].ID
		results = results[:pageSize]
	}

	return results, nextToken, nil
}

func statusToString(s Status) string  { return s.String() }
func typeToString(t Type) string      { return t.String() }
func priorityToString(p Priority) string { return p.String() }

func statusFromString(s string) Status {
	switch s {
	case "pending":
		return StatusPending
	case "resolved":
		return StatusResolved
	case "timed_out":
		return StatusTimedOut
	default:
		return 0
	}
}

func typeFromString(s string) Type {
	switch s {
	case "tripwire_escalation":
		return TypeTripwireEscalation
	case "payload_review":
		return TypePayloadReview
	case "report_review":
		return TypeReportReview
	default:
		return 0
	}
}

func priorityFromString(s string) Priority {
	switch s {
	case "low":
		return PriorityLow
	case "medium":
		return PriorityMedium
	case "high":
		return PriorityHigh
	case "critical":
		return PriorityCritical
	default:
		return 0
	}
}

func nullIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
