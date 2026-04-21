package grpc

import (
	"context"
	"errors"
	"fmt"
	"strings"

	pb "github.com/okedeji/agentcage/api/proto"
	"github.com/okedeji/agentcage/internal/assessment"
	"github.com/okedeji/agentcage/internal/cage"
	"github.com/okedeji/agentcage/internal/fleet"
	"github.com/okedeji/agentcage/internal/intervention"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Services holds references to all domain servers needed by gRPC adapters.
type Services struct {
	Cages         *cage.Service
	Assessments   *assessment.Service
	Interventions *intervention.Service
	Fleet         *fleet.Service
	Cancel        context.CancelFunc
	Version       string
}

// Register wires all gRPC service adapters onto the server.
func Register(srv *grpc.Server, svc Services) {
	pb.RegisterControlServiceServer(srv, &controlAdapter{cancelFunc: svc.Cancel, version: svc.Version})
	pb.RegisterCageServiceServer(srv, &cageAdapter{server: svc.Cages})
	pb.RegisterAssessmentServiceServer(srv, &assessmentAdapter{server: svc.Assessments})
	pb.RegisterInterventionServiceServer(srv, &interventionAdapter{server: svc.Interventions})
	pb.RegisterFleetServiceServer(srv, &fleetAdapter{server: svc.Fleet})
}

type controlAdapter struct {
	pb.UnimplementedControlServiceServer
	cancelFunc context.CancelFunc
	version    string
}

func (a *controlAdapter) Ping(_ context.Context, _ *pb.PingRequest) (*pb.PingResponse, error) {
	return &pb.PingResponse{Version: a.version, Status: "running"}, nil
}

func (a *controlAdapter) Stop(_ context.Context, _ *pb.StopRequest) (*pb.StopResponse, error) {
	a.cancelFunc()
	return &pb.StopResponse{}, nil
}

func (a *controlAdapter) Health(_ context.Context, _ *pb.HealthRequest) (*pb.HealthResponse, error) {
	return &pb.HealthResponse{Services: map[string]string{"status": "ok"}}, nil
}

type cageAdapter struct {
	pb.UnimplementedCageServiceServer
	server *cage.Service
}

func (a *cageAdapter) CreateCage(ctx context.Context, req *pb.CreateCageRequest) (*pb.CreateCageResponse, error) {
	info, err := a.server.CreateCage(ctx, cageConfigFromProto(req.GetConfig()))
	if err != nil {
		return nil, toGRPCError(err)
	}
	return &pb.CreateCageResponse{Cage: cageInfoToProto(info)}, nil
}

func (a *cageAdapter) GetCage(ctx context.Context, req *pb.GetCageRequest) (*pb.GetCageResponse, error) {
	info, err := a.server.GetCage(ctx, req.GetCageId())
	if err != nil {
		return nil, toGRPCError(err)
	}
	return &pb.GetCageResponse{Cage: cageInfoToProto(info)}, nil
}

func (a *cageAdapter) DestroyCage(ctx context.Context, req *pb.DestroyCageRequest) (*pb.DestroyCageResponse, error) {
	if err := a.server.DestroyCage(ctx, req.GetCageId(), req.GetReason()); err != nil {
		return nil, toGRPCError(err)
	}
	return &pb.DestroyCageResponse{}, nil
}

type assessmentAdapter struct {
	pb.UnimplementedAssessmentServiceServer
	server *assessment.Service
}

const (
	maxTagCount    = 50
	maxTagKeyLen   = 128
	maxTagValueLen = 1024
)

func validateTags(tags map[string]string) error {
	if len(tags) > maxTagCount {
		return fmt.Errorf("tags has %d entries, max %d", len(tags), maxTagCount)
	}
	for k, v := range tags {
		if len(k) > maxTagKeyLen {
			return fmt.Errorf("tag key %q exceeds %d characters", k, maxTagKeyLen)
		}
		if len(v) > maxTagValueLen {
			return fmt.Errorf("tag value for key %q exceeds %d characters", k, maxTagValueLen)
		}
	}
	return nil
}

func (a *assessmentAdapter) CreateAssessment(ctx context.Context, req *pb.CreateAssessmentRequest) (*pb.CreateAssessmentResponse, error) {
	if err := validateTags(req.GetConfig().GetTags()); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid tags: %v", err)
	}
	cfg := assessmentConfigFromProto(req.GetConfig())
	cfg.BundleRef = req.GetBundleRef()
	info, err := a.server.CreateAssessment(ctx, cfg)
	if err != nil {
		return nil, toGRPCError(err)
	}
	return &pb.CreateAssessmentResponse{Assessment: assessmentInfoToProto(info)}, nil
}

func (a *assessmentAdapter) GetAssessment(ctx context.Context, req *pb.GetAssessmentRequest) (*pb.GetAssessmentResponse, error) {
	info, err := a.server.GetAssessment(ctx, req.GetAssessmentId())
	if err != nil {
		return nil, toGRPCError(err)
	}
	return &pb.GetAssessmentResponse{Assessment: assessmentInfoToProto(info)}, nil
}

type interventionAdapter struct {
	pb.UnimplementedInterventionServiceServer
	server *intervention.Service
}

func (a *interventionAdapter) ListInterventions(ctx context.Context, req *pb.ListInterventionsRequest) (*pb.ListInterventionsResponse, error) {
	filters := intervention.ListFilters{
		AssessmentID: req.GetAssessmentIdFilter(),
		PageSize:     int(req.GetPageSize()),
		PageToken:    req.GetPageToken(),
	}
	if req.GetStatusFilter() != pb.InterventionStatus_INTERVENTION_STATUS_UNSPECIFIED {
		s := interventionStatusFromProto(req.GetStatusFilter())
		filters.StatusFilter = &s
	}
	if req.GetTypeFilter() != pb.InterventionType_INTERVENTION_TYPE_UNSPECIFIED {
		t := interventionTypeFromProto(req.GetTypeFilter())
		filters.TypeFilter = &t
	}

	items, err := a.server.ListInterventions(ctx, filters)
	if err != nil {
		return nil, toGRPCError(err)
	}

	pbItems := make([]*pb.InterventionInfo, len(items))
	for i, item := range items {
		pbItems[i] = interventionToProto(&item)
	}
	return &pb.ListInterventionsResponse{Interventions: pbItems}, nil
}

func (a *interventionAdapter) ResolveCageIntervention(ctx context.Context, req *pb.ResolveCageInterventionRequest) (*pb.ResolveCageInterventionResponse, error) {
	action := interventionActionFromProto(req.GetAction())
	if err := a.server.ResolveCageIntervention(ctx, req.GetInterventionId(), action, req.GetRationale(), req.GetAdjustments(), "operator"); err != nil {
		return nil, toGRPCError(err)
	}
	return &pb.ResolveCageInterventionResponse{}, nil
}

func (a *interventionAdapter) ResolveProofGap(ctx context.Context, req *pb.ResolveProofGapRequest) (*pb.ResolveProofGapResponse, error) {
	action := proofGapActionFromProto(req.GetAction())
	if err := a.server.ResolveProofGap(ctx, req.GetInterventionId(), action, req.GetRationale(), "operator"); err != nil {
		return nil, toGRPCError(err)
	}
	return &pb.ResolveProofGapResponse{}, nil
}

func (a *interventionAdapter) ResolveAssessmentReview(ctx context.Context, req *pb.ResolveAssessmentReviewRequest) (*pb.ResolveAssessmentReviewResponse, error) {
	decision := reviewDecisionFromProto(req.GetDecision())
	var adjustments []intervention.FindingAdjustment
	for _, adj := range req.GetAdjustments() {
		adjustments = append(adjustments, intervention.FindingAdjustment{
			FindingID:        adj.GetFindingId(),
			SeverityOverride: adj.GetSeverityOverride(),
			Rationale:        adj.GetRationale(),
		})
	}
	if err := a.server.ResolveAssessmentReview(ctx, req.GetInterventionId(), decision, req.GetRationale(), adjustments, "operator"); err != nil {
		return nil, toGRPCError(err)
	}
	return &pb.ResolveAssessmentReviewResponse{}, nil
}

type fleetAdapter struct {
	pb.UnimplementedFleetServiceServer
	server *fleet.Service
}

func (a *fleetAdapter) GetFleetStatus(ctx context.Context, _ *pb.GetFleetStatusRequest) (*pb.GetFleetStatusResponse, error) {
	fs, err := a.server.GetFleetStatus(ctx)
	if err != nil {
		return nil, toGRPCError(err)
	}
	return &pb.GetFleetStatusResponse{Status: fleetStatusToProto(fs)}, nil
}

func (a *fleetAdapter) DrainHost(ctx context.Context, req *pb.DrainHostRequest) (*pb.DrainHostResponse, error) {
	if err := a.server.DrainHost(ctx, req.GetHostId(), req.GetReason(), req.GetForce()); err != nil {
		return nil, toGRPCError(err)
	}
	return &pb.DrainHostResponse{}, nil
}

func (a *fleetAdapter) GetCapacity(ctx context.Context, _ *pb.GetCapacityRequest) (*pb.GetCapacityResponse, error) {
	pools, available, err := a.server.GetCapacity(ctx)
	if err != nil {
		return nil, toGRPCError(err)
	}
	pbPools := make([]*pb.PoolStatus, len(pools))
	for i, p := range pools {
		pbPools[i] = poolStatusToProto(p)
	}
	return &pb.GetCapacityResponse{Pools: pbPools, AvailableCageSlots: available}, nil
}

func toGRPCError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, cage.ErrCageNotFound) || errors.Is(err, assessment.ErrAssessmentNotFound) {
		return status.Error(codes.NotFound, err.Error())
	}
	if errors.Is(err, cage.ErrInvalidTransition) {
		return status.Error(codes.FailedPrecondition, err.Error())
	}
	msg := err.Error()
	for _, keyword := range []string{"validating", "invalid", "rejected"} {
		if strings.Contains(msg, keyword) {
			return status.Error(codes.InvalidArgument, msg)
		}
	}
	return status.Error(codes.Internal, msg)
}
