package agentcage

import (
	"context"
	"fmt"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	pb "github.com/okedeji/agentcage/api/proto"
)

// Client is the agentcage Go SDK client. It wraps the gRPC API
// with ergonomic methods for running assessments and managing cages.
type Client struct {
	conn       *grpc.ClientConn
	cages      pb.CageServiceClient
	assess     pb.AssessmentServiceClient
	intervene  pb.InterventionServiceClient
	fleet      pb.FleetServiceClient
}

type ClientOption func(*clientOptions)

type clientOptions struct {
	tlsCertFile string
	spireSocket string
}

// WithTLS configures TLS for the gRPC connection using the server's CA cert.
func WithTLS(certFile string) ClientOption {
	return func(o *clientOptions) { o.tlsCertFile = certFile }
}

// WithSPIRE configures mTLS via SPIRE Workload API.
func WithSPIRE(agentSocket string) ClientOption {
	return func(o *clientOptions) { o.spireSocket = agentSocket }
}

// NewClient connects to an agentcage orchestrator at the given address.
func NewClient(addr string, opts ...ClientOption) (*Client, error) {
	var o clientOptions
	for _, opt := range opts {
		opt(&o)
	}

	var creds grpc.DialOption
	switch {
	case o.spireSocket != "":
		source, err := workloadapi.NewX509Source(context.Background(), workloadapi.WithClientOptions(workloadapi.WithAddr(o.spireSocket)))
		if err != nil {
			return nil, fmt.Errorf("connecting to SPIRE at %s: %w", o.spireSocket, err)
		}
		tlsCfg := tlsconfig.MTLSClientConfig(source, source, tlsconfig.AuthorizeAny())
		creds = grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg))
	case o.tlsCertFile != "":
		tc, err := credentials.NewClientTLSFromFile(o.tlsCertFile, "")
		if err != nil {
			return nil, fmt.Errorf("loading TLS cert %s: %w", o.tlsCertFile, err)
		}
		creds = grpc.WithTransportCredentials(tc)
	default:
		creds = grpc.WithTransportCredentials(insecure.NewCredentials())
	}

	conn, err := grpc.NewClient(addr, creds)
	if err != nil {
		return nil, fmt.Errorf("connecting to agentcage at %s: %w", addr, err)
	}

	return &Client{
		conn:      conn,
		cages:     pb.NewCageServiceClient(conn),
		assess:    pb.NewAssessmentServiceClient(conn),
		intervene: pb.NewInterventionServiceClient(conn),
		fleet:     pb.NewFleetServiceClient(conn),
	}, nil
}

// Close closes the gRPC connection.
func (c *Client) Close() error {
	return c.conn.Close()
}

// RunConfig configures a new assessment.
type RunConfig struct {
	Agent       string        // path to .cage bundle
	Target      []string      // target hosts
	TokenBudget int64         // LLM token budget (0 = use config default)
	MaxDuration time.Duration // assessment time limit (0 = use config default)
}

// Assessment represents a running or completed assessment.
type Assessment struct {
	ID     string
	client *Client
}

// Run starts a new assessment and returns a handle to track it.
func (c *Client) Run(ctx context.Context, cfg RunConfig) (*Assessment, error) {
	scope := &pb.TargetScope{
		Hosts: cfg.Target,
	}

	req := &pb.CreateAssessmentRequest{
		Config: &pb.AssessmentConfig{
			Scope: scope,
		},
	}

	if cfg.TokenBudget > 0 {
		req.Config.TotalTokenBudget = cfg.TokenBudget
	}

	resp, err := c.assess.CreateAssessment(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("creating assessment: %w", err)
	}

	return &Assessment{
		ID:     resp.Assessment.AssessmentId,
		client: c,
	}, nil
}

// Status returns the current assessment status.
func (a *Assessment) Status(ctx context.Context) (*pb.AssessmentInfo, error) {
	resp, err := a.client.assess.GetAssessment(ctx, &pb.GetAssessmentRequest{
		AssessmentId: a.ID,
	})
	if err != nil {
		return nil, fmt.Errorf("getting assessment %s: %w", a.ID, err)
	}
	return resp.Assessment, nil
}

// Wait polls until the assessment reaches a terminal state (approved/rejected).
func (a *Assessment) Wait(ctx context.Context) (*pb.AssessmentInfo, error) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ticker.C:
			info, err := a.Status(ctx)
			if err != nil {
				return nil, err
			}
			switch info.Status {
			case pb.AssessmentStatus_ASSESSMENT_STATUS_APPROVED,
				pb.AssessmentStatus_ASSESSMENT_STATUS_REJECTED:
				return info, nil
			}
		}
	}
}

// Test creates a single cage for agent development/debugging.
// No assessment workflow, no coordinator — just one cage.
func (c *Client) Test(ctx context.Context, cfg RunConfig) (string, error) {
	scope := &pb.TargetScope{
		Hosts: cfg.Target,
	}

	req := &pb.CreateCageRequest{
		Config: &pb.CageConfig{
			Type:  pb.CageType_CAGE_TYPE_DISCOVERY,
			Scope: scope,
		},
	}

	resp, err := c.cages.CreateCage(ctx, req)
	if err != nil {
		return "", fmt.Errorf("creating test cage: %w", err)
	}

	return resp.Cage.CageId, nil
}

// Interventions lists pending interventions.
func (c *Client) Interventions(ctx context.Context) ([]*pb.InterventionInfo, error) {
	resp, err := c.intervene.ListInterventions(ctx, &pb.ListInterventionsRequest{
		StatusFilter: pb.InterventionStatus_INTERVENTION_STATUS_PENDING,
	})
	if err != nil {
		return nil, fmt.Errorf("listing interventions: %w", err)
	}
	return resp.Interventions, nil
}

// Resolve resolves a cage intervention.
func (c *Client) Resolve(ctx context.Context, interventionID string, action pb.InterventionAction, rationale string) error {
	_, err := c.intervene.ResolveCageIntervention(ctx, &pb.ResolveCageInterventionRequest{
		InterventionId: interventionID,
		Action:         action,
		Rationale:      rationale,
	})
	if err != nil {
		return fmt.Errorf("resolving intervention %s: %w", interventionID, err)
	}
	return nil
}

// FleetStatus returns the current fleet status.
func (c *Client) FleetStatus(ctx context.Context) (*pb.FleetStatus, error) {
	resp, err := c.fleet.GetFleetStatus(ctx, &pb.GetFleetStatusRequest{})
	if err != nil {
		return nil, fmt.Errorf("getting fleet status: %w", err)
	}
	return resp.Status, nil
}
