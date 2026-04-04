package cage

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

	"github.com/okedeji/agentcage/internal/intervention"
)

const TaskQueue = "cage-lifecycle"

var ErrCageNotFound = errors.New("cage not found")

type ConfigValidator func(Config) error

type Service struct {
	temporal client.Client
	validate ConfigValidator
	db       *sql.DB
	mu       sync.RWMutex
	cages    map[string]*Info
}

func NewService(temporal client.Client, validate ConfigValidator, db *sql.DB) *Service {
	return &Service{
		temporal: temporal,
		validate: validate,
		db:       db,
		cages:    make(map[string]*Info),
	}
}

func (s *Service) CreateCage(ctx context.Context, config Config) (*Info, error) {
	if err := s.validate(config); err != nil {
		return nil, fmt.Errorf("validating cage config: %w", err)
	}

	cageID := uuid.NewString()
	now := time.Now()
	info := &Info{
		ID:           cageID,
		AssessmentID: config.AssessmentID,
		Type:         config.Type,
		State:        StatePending,
		Config:       config,
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	if err := s.persistCage(ctx, info); err != nil {
		return nil, fmt.Errorf("persisting cage %s: %w", cageID, err)
	}

	s.mu.Lock()
	s.cages[cageID] = info
	s.mu.Unlock()

	workflowOpts := client.StartWorkflowOptions{
		ID:        "cage-" + cageID,
		TaskQueue: TaskQueue,
	}
	input := CageWorkflowInput{
		CageID: cageID,
		Config: config,
	}

	if _, err := s.temporal.ExecuteWorkflow(ctx, workflowOpts, CageWorkflow, input); err != nil {
		s.mu.Lock()
		delete(s.cages, cageID)
		s.mu.Unlock()
		return nil, fmt.Errorf("starting cage workflow for cage %s: %w", cageID, err)
	}

	return info, nil
}

func (s *Service) GetCage(ctx context.Context, cageID string) (*Info, error) {
	s.mu.RLock()
	info, ok := s.cages[cageID]
	s.mu.RUnlock()
	if ok {
		return info, nil
	}

	info, err := s.loadCage(ctx, cageID)
	if err != nil {
		return nil, err
	}

	s.mu.Lock()
	s.cages[cageID] = info
	s.mu.Unlock()
	return info, nil
}

func (s *Service) DestroyCage(ctx context.Context, cageID string, reason string) error {
	info, err := s.GetCage(ctx, cageID)
	if err != nil {
		return err
	}

	s.mu.Lock()
	if err := ValidateTransition(info.State, StateTearingDown); err != nil {
		s.mu.Unlock()
		return fmt.Errorf("cage %s: %w", cageID, err)
	}

	info.State = StateTearingDown
	info.UpdatedAt = time.Now()
	s.mu.Unlock()

	_ = s.updateCageState(ctx, cageID, info.State)

	signal := intervention.InterventionSignal{
		Action:    intervention.ActionKill,
		Rationale: reason,
	}
	if err := s.temporal.SignalWorkflow(ctx, "cage-"+cageID, "", intervention.SignalIntervention, signal); err != nil {
		return fmt.Errorf("signaling cage %s workflow to kill: %w", cageID, err)
	}

	return nil
}

func (s *Service) persistCage(ctx context.Context, info *Info) error {
	if s.db == nil {
		return nil
	}
	cfgJSON, err := json.Marshal(info.Config)
	if err != nil {
		return fmt.Errorf("marshaling cage config: %w", err)
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO cages (id, assessment_id, type, state, config, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)
		 ON CONFLICT (id) DO NOTHING`,
		info.ID, info.AssessmentID, info.Type.String(), info.State.String(), cfgJSON, info.CreatedAt, info.UpdatedAt,
	)
	return err
}

func (s *Service) updateCageState(ctx context.Context, cageID string, state State) error {
	if s.db == nil {
		return nil
	}
	_, err := s.db.ExecContext(ctx,
		`UPDATE cages SET state = $1, updated_at = $2 WHERE id = $3`,
		state.String(), time.Now(), cageID,
	)
	return err
}

func (s *Service) loadCage(ctx context.Context, cageID string) (*Info, error) {
	if s.db == nil {
		return nil, fmt.Errorf("cage %s: %w", cageID, ErrCageNotFound)
	}

	var (
		info     Info
		typStr   string
		stateStr string
		cfgJSON  []byte
	)
	err := s.db.QueryRowContext(ctx,
		`SELECT id, assessment_id, type, state, config, created_at, updated_at FROM cages WHERE id = $1`,
		cageID,
	).Scan(&info.ID, &info.AssessmentID, &typStr, &stateStr, &cfgJSON, &info.CreatedAt, &info.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("cage %s: %w", cageID, ErrCageNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("loading cage %s: %w", cageID, err)
	}

	info.Type = TypeFromString(typStr)
	info.State = StateFromString(stateStr)
	_ = json.Unmarshal(cfgJSON, &info.Config)
	return &info, nil
}
