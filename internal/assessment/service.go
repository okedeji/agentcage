package assessment

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
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
	temporal    client.Client
	db          *sql.DB
	fleet       FleetSignaler
	mu          sync.RWMutex
	assessments map[string]*Info
}

func NewService(temporal client.Client, db *sql.DB, fleet FleetSignaler) *Service {
	return &Service{
		temporal:    temporal,
		db:          db,
		fleet:       fleet,
		assessments: make(map[string]*Info),
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
