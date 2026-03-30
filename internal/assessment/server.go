package assessment

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.temporal.io/sdk/client"
)

const TaskQueue = "assessment-lifecycle"

var ErrAssessmentNotFound = errors.New("assessment not found")

type Server struct {
	temporal    client.Client
	mu          sync.RWMutex
	assessments map[string]*Info
}

func NewServer(temporal client.Client) *Server {
	return &Server{
		temporal:    temporal,
		assessments: make(map[string]*Info),
	}
}

func (s *Server) CreateAssessment(ctx context.Context, config Config) (*Info, error) {
	assessmentID := uuid.NewString()
	now := time.Now()
	info := &Info{
		ID:         assessmentID,
		CustomerID: config.CustomerID,
		Status:     StatusMapping,
		Config:     config,
		CreatedAt:  now,
		UpdatedAt:  now,
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

	return info, nil
}

func (s *Server) GetAssessment(_ context.Context, assessmentID string) (*Info, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	info, ok := s.assessments[assessmentID]
	if !ok {
		return nil, fmt.Errorf("assessment %s: %w", assessmentID, ErrAssessmentNotFound)
	}
	return info, nil
}
