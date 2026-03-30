package cage

import (
	"context"
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

type Server struct {
	temporal client.Client
	validate ConfigValidator
	mu       sync.RWMutex
	cages    map[string]*Info
}

func NewServer(temporal client.Client, validate ConfigValidator) *Server {
	return &Server{
		temporal: temporal,
		validate: validate,
		cages:    make(map[string]*Info),
	}
}

func (s *Server) CreateCage(ctx context.Context, config Config) (*Info, error) {
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

func (s *Server) GetCage(_ context.Context, cageID string) (*Info, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	info, ok := s.cages[cageID]
	if !ok {
		return nil, fmt.Errorf("cage %s: %w", cageID, ErrCageNotFound)
	}
	return info, nil
}

func (s *Server) DestroyCage(ctx context.Context, cageID string, reason string) error {
	s.mu.Lock()
	info, ok := s.cages[cageID]
	if !ok {
		s.mu.Unlock()
		return fmt.Errorf("cage %s: %w", cageID, ErrCageNotFound)
	}

	if err := ValidateTransition(info.State, StateTearingDown); err != nil {
		s.mu.Unlock()
		return fmt.Errorf("cage %s: %w", cageID, err)
	}

	info.State = StateTearingDown
	info.UpdatedAt = time.Now()
	s.mu.Unlock()

	signal := intervention.InterventionSignal{
		Action:    intervention.ActionKill,
		Rationale: reason,
	}
	if err := s.temporal.SignalWorkflow(ctx, "cage-"+cageID, "", intervention.SignalIntervention, signal); err != nil {
		return fmt.Errorf("signaling cage %s workflow to kill: %w", cageID, err)
	}

	return nil
}
