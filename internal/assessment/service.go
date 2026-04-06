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

	"github.com/okedeji/agentcage/internal/cage"
	"github.com/okedeji/agentcage/internal/findings"
)

const TaskQueue = "assessment-lifecycle"

var (
	ErrAssessmentNotFound  = errors.New("assessment not found")
	ErrFindingNotFound     = errors.New("finding not found")
	ErrProofUnavailable    = errors.New("no proof available for vuln class")
	ErrAssessmentFinalized = errors.New("assessment is finalized")
)

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
	cages       *cage.Service
	findings    findings.FindingStore
	proofs      *ProofLibrary
	mu          sync.RWMutex
	assessments map[string]*Info
}

func NewService(temporal client.Client, db *sql.DB, fleet FleetSignaler, cages *cage.Service, findingStore findings.FindingStore, proofs *ProofLibrary) *Service {
	return &Service{
		temporal:    temporal,
		db:          db,
		fleet:       fleet,
		cages:       cages,
		findings:    findingStore,
		proofs:      proofs,
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

// RevalidateFinding spawns a one-off validator cage for an existing candidate
// finding, using the named proof or the first available proof for the
// finding's vuln class. Operator-initiated; used after adding new proofs.
func (s *Service) RevalidateFinding(ctx context.Context, findingID, vulnClass, proofName string) (string, error) {
	if s.findings == nil {
		return "", fmt.Errorf("finding store not configured")
	}
	if s.proofs == nil {
		return "", fmt.Errorf("proof library not configured")
	}
	if s.cages == nil {
		return "", fmt.Errorf("cage service not configured")
	}

	finding, err := s.loadFinding(ctx, findingID)
	if err != nil {
		return "", err
	}

	// Reject revalidation against assessments in a finalized state — a
	// validator cage spawned now would mutate findings on a report that
	// has already been approved or rejected.
	parent, err := s.GetAssessment(ctx, finding.AssessmentID)
	if err != nil {
		return "", fmt.Errorf("loading parent assessment %s: %w", finding.AssessmentID, err)
	}
	if parent.Status == StatusApproved || parent.Status == StatusRejected {
		return "", fmt.Errorf("%w: %s is %s", ErrAssessmentFinalized, parent.ID, parent.Status)
	}

	// Override vuln class if operator specified one
	effectiveVulnClass := finding.VulnClass
	if vulnClass != "" {
		effectiveVulnClass = vulnClass
	}

	var proof *Proof
	if proofName != "" {
		proof, err = s.proofs.Get(effectiveVulnClass, proofName)
		if err != nil {
			return "", fmt.Errorf("loading proof %s for vuln class %s: %w", proofName, effectiveVulnClass, err)
		}
	} else {
		available := s.proofs.GetByVulnClass(effectiveVulnClass)
		if len(available) == 0 {
			return "", fmt.Errorf("%w: %s", ErrProofUnavailable, effectiveVulnClass)
		}
		proof = available[0]
	}

	proofJSON, err := json.Marshal(proof)
	if err != nil {
		return "", fmt.Errorf("marshaling proof for finding %s: %w", findingID, err)
	}

	cageCfg := cage.Config{
		AssessmentID:    finding.AssessmentID,
		Type:            cage.TypeValidator,
		Scope:           cage.Scope{Hosts: []string{finding.Endpoint}},
		ParentFindingID: finding.ID,
		InputContext:    proofJSON,
	}

	info, err := s.cages.CreateCage(ctx, cageCfg)
	if err != nil {
		return "", fmt.Errorf("creating revalidation cage for finding %s: %w", findingID, err)
	}

	return info.ID, nil
}

func (s *Service) loadFinding(ctx context.Context, findingID string) (*findings.Finding, error) {
	f, err := s.findings.GetByID(ctx, findingID)
	if err != nil {
		if errors.Is(err, findings.ErrFindingNotFound) {
			return nil, fmt.Errorf("%w: %s", ErrFindingNotFound, findingID)
		}
		return nil, fmt.Errorf("loading finding %s: %w", findingID, err)
	}
	return &f, nil
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
