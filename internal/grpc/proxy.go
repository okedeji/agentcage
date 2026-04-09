package grpc

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	pb "github.com/okedeji/agentcage/api/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const ProxyTarget = "localhost:9090"

// Proxy dials the gRPC server and dispatches the command.
func Proxy(cmd string, args []string) {
	conn, err := grpc.NewClient(ProxyTarget,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		fmt.Fprintln(os.Stderr, "agentcage is not running. Run 'agentcage init' first.")
		os.Exit(1)
	}
	defer func() { _ = conn.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	control := pb.NewControlServiceClient(conn)
	if _, err := control.Ping(ctx, &pb.PingRequest{}); err != nil {
		fmt.Fprintln(os.Stderr, "agentcage is not running. Run 'agentcage init' first.")
		os.Exit(1)
	}

	switch cmd {
	case "test":
		proxyTest(conn, args)
	case "status":
		proxyStatus(conn, args)
	case "report":
		proxyReport(conn, args)
	case "interventions":
		proxyInterventions(conn, args)
	case "resolve":
		proxyResolve(conn, args)
	case "fleet":
		proxyFleet(conn, args)
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", cmd)
		os.Exit(1)
	}
}

func proxyTest(conn *grpc.ClientConn, args []string) {
	fs := flag.NewFlagSet("test", flag.ExitOnError)
	_ = fs.String("agent", "", "path to .cage bundle")
	target := fs.String("target", "", "single target endpoint")
	_ = fs.String("vuln-class", "", "vulnerability class")
	_ = fs.Parse(args)

	if *target == "" {
		fmt.Fprintln(os.Stderr, "usage: agentcage test --agent <path.cage> --target <endpoint> [--vuln-class sqli]")
		os.Exit(1)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client := pb.NewCageServiceClient(conn)
	resp, err := client.CreateCage(ctx, &pb.CreateCageRequest{
		Config: &pb.CageConfig{
			Type:  pb.CageType_CAGE_TYPE_VALIDATOR,
			Scope: &pb.TargetScope{Hosts: []string{*target}},
		},
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "error creating test cage: %v\n", err)
		os.Exit(1)
	}

	info := resp.GetCage()
	fmt.Printf("Test cage started.\n")
	fmt.Printf("  Cage ID: %s\n", info.GetCageId())
	fmt.Printf("  Target:  %s\n", *target)
	fmt.Println("\nUse 'agentcage logs --cage <id>' to stream logs.")
}

func proxyStatus(conn *grpc.ClientConn, args []string) {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	assessmentID := fs.String("assessment", "", "assessment ID")
	_ = fs.Parse(args)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if *assessmentID != "" {
		client := pb.NewAssessmentServiceClient(conn)
		resp, err := client.GetAssessment(ctx, &pb.GetAssessmentRequest{AssessmentId: *assessmentID})
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		info := resp.GetAssessment()
		fmt.Printf("Assessment %s\n", info.GetAssessmentId())
		fmt.Printf("  Status:   %s\n", info.GetStatus())
		fmt.Printf("  Customer: %s\n", info.GetCustomerId())
		if stats := info.GetStats(); stats != nil {
			fmt.Printf("  Cages:    %d total, %d active\n", stats.GetTotalCages(), stats.GetActiveCages())
			fmt.Printf("  Findings: %d candidate, %d validated, %d rejected\n",
				stats.GetFindingsCandidate(), stats.GetFindingsValidated(), stats.GetFindingsRejected())
			fmt.Printf("  Tokens:   %d consumed\n", stats.GetTokensConsumed())
		}
		return
	}

	fleet := pb.NewFleetServiceClient(conn)
	resp, err := fleet.GetFleetStatus(ctx, &pb.GetFleetStatusRequest{})
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	s := resp.GetStatus()
	fmt.Printf("Fleet: %d hosts, %.0f%% utilization\n", s.GetTotalHosts(), s.GetCapacityUtilizationRatio()*100)
	for _, p := range s.GetPools() {
		fmt.Printf("  %s: %d hosts, %d/%d cage slots\n", p.GetPool(), p.GetHostCount(), p.GetCageSlotsUsed(), p.GetCageSlotsTotal())
	}
}

func proxyReport(_ *grpc.ClientConn, _ []string) {
	fmt.Fprintln(os.Stderr, "report generation requires ReportService (not yet wired)")
	os.Exit(1)
}

func proxyInterventions(conn *grpc.ClientConn, args []string) {
	fs := flag.NewFlagSet("interventions", flag.ExitOnError)
	statusFlag := fs.String("status", "pending", "filter by status: pending, resolved, timed_out")
	_ = fs.Parse(args)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var statusFilter pb.InterventionStatus
	switch *statusFlag {
	case "pending":
		statusFilter = pb.InterventionStatus_INTERVENTION_STATUS_PENDING
	case "resolved":
		statusFilter = pb.InterventionStatus_INTERVENTION_STATUS_RESOLVED
	case "timed_out":
		statusFilter = pb.InterventionStatus_INTERVENTION_STATUS_TIMED_OUT
	}

	client := pb.NewInterventionServiceClient(conn)
	resp, err := client.ListInterventions(ctx, &pb.ListInterventionsRequest{
		StatusFilter: statusFilter,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	items := resp.GetInterventions()
	if len(items) == 0 {
		fmt.Printf("No %s interventions.\n", *statusFlag)
		return
	}
	for _, item := range items {
		scope := "cage=" + item.GetCageId()
		if item.GetType() == pb.InterventionType_INTERVENTION_TYPE_PROOF_GAP {
			scope = "assessment=" + item.GetAssessmentId()
		}
		fmt.Printf("  %s  %s  type=%s  %s  %s\n",
			item.GetInterventionId(),
			scope,
			interventionTypeLabel(item.GetType()),
			item.GetDescription(),
			item.GetCreatedAt().AsTime().Format(time.RFC3339),
		)
	}
}

func interventionTypeLabel(t pb.InterventionType) string {
	switch t {
	case pb.InterventionType_INTERVENTION_TYPE_TRIPWIRE_ESCALATION:
		return "tripwire"
	case pb.InterventionType_INTERVENTION_TYPE_PAYLOAD_REVIEW:
		return "payload_review"
	case pb.InterventionType_INTERVENTION_TYPE_REPORT_REVIEW:
		return "report_review"
	case pb.InterventionType_INTERVENTION_TYPE_PROOF_GAP:
		return "proof_gap"
	default:
		return "unknown"
	}
}

func proxyResolve(conn *grpc.ClientConn, args []string) {
	fs := flag.NewFlagSet("resolve", flag.ExitOnError)
	interventionID := fs.String("id", "", "intervention ID")
	action := fs.String("action", "", "action: resume, kill, allow, block, retry, skip")
	rationale := fs.String("rationale", "", "reason for the decision")
	_ = fs.Parse(args)

	if *interventionID == "" || *action == "" {
		fmt.Fprintln(os.Stderr, "usage: agentcage resolve --id <intervention-id> --action <resume|kill|allow|block|retry|skip> [--rationale reason]")
		fmt.Fprintln(os.Stderr, "  retry/skip apply to proof_gap interventions")
		os.Exit(1)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client := pb.NewInterventionServiceClient(conn)

	// proof_gap actions take a different RPC path.
	switch *action {
	case "retry", "skip":
		var pgAction pb.ProofGapAction
		if *action == "retry" {
			pgAction = pb.ProofGapAction_PROOF_GAP_ACTION_RETRY
		} else {
			pgAction = pb.ProofGapAction_PROOF_GAP_ACTION_SKIP
		}
		if _, err := client.ResolveProofGap(ctx, &pb.ResolveProofGapRequest{
			InterventionId: *interventionID,
			Action:         pgAction,
			Rationale:      *rationale,
		}); err != nil {
			fmt.Fprintf(os.Stderr, "error resolving proof_gap intervention: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Proof gap intervention %s resolved with action=%s\n", *interventionID, *action)
		return
	}

	var pbAction pb.InterventionAction
	switch *action {
	case "resume":
		pbAction = pb.InterventionAction_INTERVENTION_ACTION_RESUME
	case "kill":
		pbAction = pb.InterventionAction_INTERVENTION_ACTION_KILL
	case "allow":
		pbAction = pb.InterventionAction_INTERVENTION_ACTION_ALLOW
	case "block":
		pbAction = pb.InterventionAction_INTERVENTION_ACTION_BLOCK
	default:
		fmt.Fprintf(os.Stderr, "unknown action: %s\n", *action)
		os.Exit(1)
	}

	if _, err := client.ResolveCageIntervention(ctx, &pb.ResolveCageInterventionRequest{
		InterventionId: *interventionID,
		Action:         pbAction,
		Rationale:      *rationale,
	}); err != nil {
		fmt.Fprintf(os.Stderr, "error resolving intervention: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Intervention %s resolved with action=%s\n", *interventionID, *action)
}

func proxyFleet(conn *grpc.ClientConn, _ []string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client := pb.NewFleetServiceClient(conn)
	resp, err := client.GetFleetStatus(ctx, &pb.GetFleetStatusRequest{})
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	s := resp.GetStatus()
	fmt.Printf("Fleet: %d hosts, %.0f%% utilization\n", s.GetTotalHosts(), s.GetCapacityUtilizationRatio()*100)
	for _, p := range s.GetPools() {
		fmt.Printf("  %-15s %d hosts, %d/%d cage slots\n", p.GetPool(), p.GetHostCount(), p.GetCageSlotsUsed(), p.GetCageSlotsTotal())
	}

	capResp, err := client.GetCapacity(ctx, &pb.GetCapacityRequest{})
	if err == nil {
		fmt.Printf("\nAvailable cage slots: %d\n", capResp.GetAvailableCageSlots())
	}
}
