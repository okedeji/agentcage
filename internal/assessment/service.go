package assessment

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.temporal.io/sdk/client"
)

const TaskQueue = "assessment-lifecycle"

var ErrAssessmentNotFound = errors.New("assessment not found")

// FleetSignaler notifies the fleet about assessment lifecycle events.
// Defined as an interface to avoid importing the fleet package directly.
type FleetSignaler interface {
	OnNewAssessment(assessmentID string, surfaceSize int)
	OnAssessmentComplete(assessmentID string)
}

type Service struct {
	temporal      client.Client
	db            *sql.DB
	fleet         FleetSignaler
	maxIterations int32
	mu            sync.RWMutex
	assessments   map[string]*Info
}

func NewService(temporal client.Client, db *sql.DB, fleet FleetSignaler, maxIterations int32) *Service {
	return &Service{
		temporal:      temporal,
		db:            db,
		fleet:         fleet,
		maxIterations: maxIterations,
		assessments:   make(map[string]*Info),
	}
}

func (s *Service) CreateAssessment(ctx context.Context, config Config) (*Info, error) {
	assessmentID := uuid.NewString()
	now := time.Now()
	info := &Info{
		ID:         assessmentID,
		CustomerID: config.CustomerID,
		Status:     StatusDiscovery,
		Config:     config,
		CreatedAt:  now,
		UpdatedAt:  now,
	}

	if err := s.persistAssessment(ctx, info); err != nil {
		return nil, fmt.Errorf("persisting assessment %s: %w", assessmentID, err)
	}

	s.mu.Lock()
	s.assessments[assessmentID] = info
	s.mu.Unlock()

	workflowOpts := client.StartWorkflowOptions{
		ID:        "assessment-" + assessmentID,
		TaskQueue: TaskQueue,
	}
	if config.MaxIterations <= 0 {
		config.MaxIterations = s.maxIterations
	}
	input := AssessmentWorkflowInput{
		AssessmentID: assessmentID,
		Config:       config,
	}

	if _, err := s.temporal.ExecuteWorkflow(ctx, workflowOpts, AssessmentWorkflow, input); err != nil {
		s.mu.Lock()
		delete(s.assessments, assessmentID)
		s.mu.Unlock()
		return nil, fmt.Errorf("starting assessment workflow for assessment %s: %w", assessmentID, err)
	}

	if s.fleet != nil {
		s.fleet.OnNewAssessment(assessmentID, len(config.Target.Hosts))
	}

	return info, nil
}

func (s *Service) GetAssessment(ctx context.Context, assessmentID string) (*Info, error) {
	s.mu.RLock()
	info, ok := s.assessments[assessmentID]
	s.mu.RUnlock()
	if ok {
		return info, nil
	}

	info, err := s.loadAssessment(ctx, assessmentID)
	if err != nil {
		return nil, err
	}

	s.mu.Lock()
	s.assessments[assessmentID] = info
	s.mu.Unlock()
	return info, nil
}

type ListFilters struct {
	StatusFilter *Status
	Limit        int
	PageToken    string
}

func (s *Service) ListAssessments(ctx context.Context, filters ListFilters) ([]Info, string, error) {
	limit := filters.Limit
	if limit <= 0 || limit > 100 {
		limit = 50
	}

	if s.db == nil {
		s.mu.RLock()
		var results []Info
		for _, info := range s.assessments {
			if filters.StatusFilter != nil && info.Status != *filters.StatusFilter {
				continue
			}
			results = append(results, *info)
		}
		s.mu.RUnlock()
		sort.Slice(results, func(i, j int) bool {
			return results[i].CreatedAt.After(results[j].CreatedAt)
		})
		if len(results) > limit {
			results = results[:limit]
		}
		return results, "", nil
	}

	query := `SELECT id, customer_id, status, config, created_at, updated_at FROM assessments`
	var whereClauses []string
	var args []any
	argIdx := 1

	if filters.StatusFilter != nil {
		whereClauses = append(whereClauses, fmt.Sprintf(`status = $%d`, argIdx))
		args = append(args, filters.StatusFilter.String())
		argIdx++
	}

	if filters.PageToken != "" {
		whereClauses = append(whereClauses, fmt.Sprintf(`created_at < (SELECT created_at FROM assessments WHERE id = $%d)`, argIdx))
		args = append(args, filters.PageToken)
		argIdx++
	}

	if len(whereClauses) > 0 {
		query += ` WHERE ` + strings.Join(whereClauses, ` AND `)
	}

	query += ` ORDER BY created_at DESC`
	query += fmt.Sprintf(` LIMIT $%d`, argIdx)
	args = append(args, limit+1)

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, "", fmt.Errorf("listing assessments: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var results []Info
	for rows.Next() {
		var info Info
		var statusStr string
		var cfgJSON []byte
		if err := rows.Scan(&info.ID, &info.CustomerID, &statusStr, &cfgJSON, &info.CreatedAt, &info.UpdatedAt); err != nil {
			return nil, "", fmt.Errorf("scanning assessment row: %w", err)
		}
		info.Status = StatusFromString(statusStr)
		_ = json.Unmarshal(cfgJSON, &info.Config)
		results = append(results, info)
	}
	if err := rows.Err(); err != nil {
		return nil, "", fmt.Errorf("iterating assessment rows: %w", err)
	}

	s.mu.RLock()
	for i := range results {
		if cached, ok := s.assessments[results[i].ID]; ok {
			results[i].Stats = cached.Stats
			results[i].Status = cached.Status
		}
	}
	s.mu.RUnlock()

	// The DB filtered by persisted status, but the cache overlay may
	// have updated a row's status since the last write. Drop rows that
	// no longer match the requested filter.
	if filters.StatusFilter != nil {
		filtered := results[:0]
		for _, r := range results {
			if r.Status == *filters.StatusFilter {
				filtered = append(filtered, r)
			}
		}
		results = filtered
	}

	var nextToken string
	if len(results) > limit {
		results = results[:limit]
		nextToken = results[limit-1].ID
	}

	return results, nextToken, nil
}

func (s *Service) LoadReport(ctx context.Context, assessmentID string) ([]byte, error) {
	if s.db == nil {
		return nil, fmt.Errorf("assessment %s: report not available (no database)", assessmentID)
	}
	var report []byte
	err := s.db.QueryRowContext(ctx,
		`SELECT report FROM assessments WHERE id = $1`, assessmentID,
	).Scan(&report)
	if err != nil {
		return nil, fmt.Errorf("loading report for assessment %s: %w", assessmentID, err)
	}
	if report == nil {
		return nil, fmt.Errorf("assessment %s: no report generated yet", assessmentID)
	}
	return report, nil
}

func (s *Service) UpdateStatus(ctx context.Context, assessmentID string, status Status) error {
	s.mu.Lock()
	info, ok := s.assessments[assessmentID]
	if ok {
		info.Status = status
		info.UpdatedAt = time.Now()
	}
	s.mu.Unlock()

	if s.db == nil {
		return nil
	}
	_, err := s.db.ExecContext(ctx,
		`UPDATE assessments SET status = $1, updated_at = $2 WHERE id = $3`,
		status.String(), time.Now(), assessmentID,
	)
	if err != nil {
		return fmt.Errorf("updating assessment %s status to %s: %w", assessmentID, status, err)
	}
	return nil
}

func (s *Service) UpdateStats(ctx context.Context, assessmentID string, stats Stats) error {
	s.mu.Lock()
	info, ok := s.assessments[assessmentID]
	if ok {
		info.Stats = stats
		info.UpdatedAt = time.Now()
	}
	s.mu.Unlock()

	if s.db == nil {
		return nil
	}
	_, err := s.db.ExecContext(ctx,
		`UPDATE assessments SET updated_at = $1 WHERE id = $2`,
		time.Now(), assessmentID,
	)
	if err != nil {
		return fmt.Errorf("updating assessment %s stats: %w", assessmentID, err)
	}
	return nil
}

func (s *Service) persistAssessment(ctx context.Context, info *Info) error {
	if s.db == nil {
		return nil
	}
	cfgJSON, err := json.Marshal(info.Config)
	if err != nil {
		return fmt.Errorf("marshaling assessment config: %w", err)
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO assessments (id, customer_id, status, config, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6)
		 ON CONFLICT (id) DO NOTHING`,
		info.ID, info.CustomerID, info.Status.String(), cfgJSON, info.CreatedAt, info.UpdatedAt,
	)
	return err
}

func (s *Service) loadAssessment(ctx context.Context, assessmentID string) (*Info, error) {
	if s.db == nil {
		return nil, fmt.Errorf("assessment %s: %w", assessmentID, ErrAssessmentNotFound)
	}

	var (
		info      Info
		statusStr string
		cfgJSON   []byte
	)
	err := s.db.QueryRowContext(ctx,
		`SELECT id, customer_id, status, config, created_at, updated_at FROM assessments WHERE id = $1`,
		assessmentID,
	).Scan(&info.ID, &info.CustomerID, &statusStr, &cfgJSON, &info.CreatedAt, &info.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("assessment %s: %w", assessmentID, ErrAssessmentNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("loading assessment %s: %w", assessmentID, err)
	}

	info.Status = StatusFromString(statusStr)
	_ = json.Unmarshal(cfgJSON, &info.Config)
	return &info, nil
}
