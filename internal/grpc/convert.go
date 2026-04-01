package grpc

import (
	pb "github.com/okedeji/agentcage/api/proto"
	"github.com/okedeji/agentcage/internal/assessment"
	"github.com/okedeji/agentcage/internal/cage"
	"github.com/okedeji/agentcage/internal/fleet"
	"github.com/okedeji/agentcage/internal/intervention"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func cageConfigFromProto(p *pb.CageConfig) cage.Config {
	if p == nil {
		return cage.Config{}
	}
	cfg := cage.Config{
		AssessmentID: p.GetAssessmentId(),
		Type:         cageTypeFromProto(p.GetType()),
	}
	if s := p.GetScope(); s != nil {
		cfg.Scope = cage.Scope{Hosts: s.GetHosts(), Ports: s.GetPorts(), Paths: s.GetPaths(), Extras: s.GetExtras()}
	}
	if r := p.GetResources(); r != nil {
		cfg.Resources = cage.ResourceLimits{VCPUs: r.GetVcpus(), MemoryMB: r.GetMemoryMb()}
	}
	if t := p.GetTimeLimits(); t != nil && t.GetMaxDuration() != nil {
		cfg.TimeLimits = cage.TimeLimits{MaxDuration: t.GetMaxDuration().AsDuration()}
	}
	if r := p.GetRateLimits(); r != nil {
		cfg.RateLimits = cage.RateLimits{RequestsPerSecond: r.GetRequestsPerSecond()}
	}
	return cfg
}

func cageTypeFromProto(t pb.CageType) cage.Type {
	switch t {
	case pb.CageType_CAGE_TYPE_DISCOVERY:
		return cage.TypeDiscovery
	case pb.CageType_CAGE_TYPE_VALIDATOR:
		return cage.TypeValidator
	case pb.CageType_CAGE_TYPE_ESCALATION:
		return cage.TypeEscalation
	default:
		return cage.TypeDiscovery
	}
}

func cageTypeToProto(t cage.Type) pb.CageType {
	switch t {
	case cage.TypeDiscovery:
		return pb.CageType_CAGE_TYPE_DISCOVERY
	case cage.TypeValidator:
		return pb.CageType_CAGE_TYPE_VALIDATOR
	case cage.TypeEscalation:
		return pb.CageType_CAGE_TYPE_ESCALATION
	default:
		return pb.CageType_CAGE_TYPE_UNSPECIFIED
	}
}

func cageStateToProto(s cage.State) pb.CageState {
	switch s {
	case cage.StatePending:
		return pb.CageState_CAGE_STATE_PENDING
	case cage.StateProvisioning:
		return pb.CageState_CAGE_STATE_PROVISIONING
	case cage.StateRunning:
		return pb.CageState_CAGE_STATE_RUNNING
	case cage.StatePaused:
		return pb.CageState_CAGE_STATE_PAUSED
	case cage.StateTearingDown:
		return pb.CageState_CAGE_STATE_TEARING_DOWN
	case cage.StateCompleted:
		return pb.CageState_CAGE_STATE_COMPLETED
	case cage.StateFailed:
		return pb.CageState_CAGE_STATE_FAILED
	default:
		return pb.CageState_CAGE_STATE_UNSPECIFIED
	}
}

func cageInfoToProto(info *cage.Info) *pb.CageInfo {
	return &pb.CageInfo{
		CageId:       info.ID,
		AssessmentId: info.AssessmentID,
		Type:         cageTypeToProto(info.Type),
		State:        cageStateToProto(info.State),
		CreatedAt:    timestamppb.New(info.CreatedAt),
		UpdatedAt:    timestamppb.New(info.UpdatedAt),
	}
}

func assessmentConfigFromProto(p *pb.AssessmentConfig) assessment.Config {
	if p == nil {
		return assessment.Config{}
	}
	cfg := assessment.Config{
		CustomerID: p.GetCustomerId(),
	}
	if s := p.GetScope(); s != nil {
		cfg.Target = cage.Scope{Hosts: s.GetHosts(), Ports: s.GetPorts(), Paths: s.GetPaths(), Extras: s.GetExtras()}
	}
	if p.GetTotalTokenBudget() > 0 {
		cfg.TokenBudget = p.GetTotalTokenBudget()
	}
	if p.GetMaxDuration() != nil {
		cfg.MaxDuration = p.GetMaxDuration().AsDuration()
	}
	if p.GetMaxChainDepth() > 0 {
		cfg.MaxChainDepth = p.GetMaxChainDepth()
	}
	return cfg
}

func assessmentStatusToProto(s assessment.Status) pb.AssessmentStatus {
	switch s {
	case assessment.StatusDiscovery:
		return pb.AssessmentStatus_ASSESSMENT_STATUS_DISCOVERY
	case assessment.StatusExploitation:
		return pb.AssessmentStatus_ASSESSMENT_STATUS_EXPLOITATION
	case assessment.StatusValidation:
		return pb.AssessmentStatus_ASSESSMENT_STATUS_VALIDATION
	case assessment.StatusPendingReview:
		return pb.AssessmentStatus_ASSESSMENT_STATUS_PENDING_REVIEW
	case assessment.StatusApproved:
		return pb.AssessmentStatus_ASSESSMENT_STATUS_APPROVED
	case assessment.StatusRejected:
		return pb.AssessmentStatus_ASSESSMENT_STATUS_REJECTED
	default:
		return pb.AssessmentStatus_ASSESSMENT_STATUS_UNSPECIFIED
	}
}

func assessmentInfoToProto(info *assessment.Info) *pb.AssessmentInfo {
	return &pb.AssessmentInfo{
		AssessmentId: info.ID,
		CustomerId:   info.CustomerID,
		Status:       assessmentStatusToProto(info.Status),
		Stats: &pb.AssessmentStats{
			TotalCages:        info.Stats.TotalCages,
			ActiveCages:       info.Stats.ActiveCages,
			FindingsCandidate: info.Stats.FindingsCandidate,
			FindingsValidated: info.Stats.FindingsValidated,
			FindingsRejected:  info.Stats.FindingsRejected,
			TokensConsumed:    info.Stats.TokensConsumed,
		},
		CreatedAt: timestamppb.New(info.CreatedAt),
		UpdatedAt: timestamppb.New(info.UpdatedAt),
	}
}

func interventionStatusFromProto(s pb.InterventionStatus) intervention.Status {
	switch s {
	case pb.InterventionStatus_INTERVENTION_STATUS_PENDING:
		return intervention.StatusPending
	case pb.InterventionStatus_INTERVENTION_STATUS_RESOLVED:
		return intervention.StatusResolved
	case pb.InterventionStatus_INTERVENTION_STATUS_TIMED_OUT:
		return intervention.StatusTimedOut
	default:
		return intervention.StatusPending
	}
}

func interventionTypeFromProto(t pb.InterventionType) intervention.Type {
	switch t {
	case pb.InterventionType_INTERVENTION_TYPE_TRIPWIRE_ESCALATION:
		return intervention.TypeTripwireEscalation
	case pb.InterventionType_INTERVENTION_TYPE_PAYLOAD_REVIEW:
		return intervention.TypePayloadReview
	case pb.InterventionType_INTERVENTION_TYPE_REPORT_REVIEW:
		return intervention.TypeReportReview
	default:
		return intervention.TypeTripwireEscalation
	}
}

func interventionActionFromProto(a pb.InterventionAction) intervention.Action {
	switch a {
	case pb.InterventionAction_INTERVENTION_ACTION_RESUME:
		return intervention.ActionResume
	case pb.InterventionAction_INTERVENTION_ACTION_ADJUST_AND_RESUME:
		return intervention.ActionAdjustAndResume
	case pb.InterventionAction_INTERVENTION_ACTION_KILL:
		return intervention.ActionKill
	case pb.InterventionAction_INTERVENTION_ACTION_ALLOW:
		return intervention.ActionAllow
	case pb.InterventionAction_INTERVENTION_ACTION_BLOCK:
		return intervention.ActionBlock
	default:
		return intervention.ActionResume
	}
}

func reviewDecisionFromProto(d pb.ReviewDecision) intervention.ReviewDecision {
	switch d {
	case pb.ReviewDecision_REVIEW_DECISION_APPROVE:
		return intervention.ReviewApprove
	case pb.ReviewDecision_REVIEW_DECISION_REQUEST_RETEST:
		return intervention.ReviewRequestRetest
	case pb.ReviewDecision_REVIEW_DECISION_REJECT:
		return intervention.ReviewReject
	default:
		return intervention.ReviewApprove
	}
}

func interventionToProto(r *intervention.Request) *pb.InterventionInfo {
	info := &pb.InterventionInfo{
		InterventionId: r.ID,
		CageId:         r.CageID,
		AssessmentId:   r.AssessmentID,
		Description:    r.Description,
		CreatedAt:      timestamppb.New(r.CreatedAt),
	}
	if r.Timeout > 0 {
		info.Timeout = durationpb.New(r.Timeout)
	}
	return info
}

func fleetStatusToProto(fs fleet.FleetStatus) *pb.FleetStatus {
	pbPools := make([]*pb.PoolStatus, len(fs.Pools))
	for i, p := range fs.Pools {
		pbPools[i] = poolStatusToProto(p)
	}
	return &pb.FleetStatus{
		TotalHosts:               fs.TotalHosts,
		Pools:                    pbPools,
		CapacityUtilizationRatio: float32(fs.CapacityUtilizationRatio),
	}
}

func poolStatusToProto(ps fleet.PoolStatus) *pb.PoolStatus {
	return &pb.PoolStatus{
		Pool:           poolToProto(ps.Pool),
		HostCount:      ps.HostCount,
		CageSlotsTotal: ps.CageSlotsTotal,
		CageSlotsUsed:  ps.CageSlotsUsed,
	}
}

func poolToProto(p fleet.HostPool) pb.HostPool {
	switch p {
	case fleet.PoolActive:
		return pb.HostPool_HOST_POOL_ACTIVE
	case fleet.PoolWarm:
		return pb.HostPool_HOST_POOL_WARM
	case fleet.PoolProvisioning:
		return pb.HostPool_HOST_POOL_PROVISIONING
	case fleet.PoolDraining:
		return pb.HostPool_HOST_POOL_DRAINING
	default:
		return pb.HostPool_HOST_POOL_UNSPECIFIED
	}
}
