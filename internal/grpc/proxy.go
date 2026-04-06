package grpc

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	pb "github.com/okedeji/agentcage/api/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/durationpb"
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
	case "run":
		proxyRun(conn, args)
	case "test":
		proxyTest(conn, args)
	case "status":
		proxyStatus(conn, args)
	case "findings":
		proxyFindings(conn, args)
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

func proxyRun(conn *grpc.ClientConn, args []string) {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	agent := fs.String("agent", "", "path to .cage bundle or agent directory")
	target := fs.String("target", "", "target host(s), comma-separated")
	tokenBudget := fs.Int64("token-budget", 0, "LLM token budget")
	maxDuration := fs.String("max-duration", "", "assessment time limit (e.g. 30m, 4h)")
	_ = fs.Parse(args)

	if *agent == "" || *target == "" {
		fmt.Fprintln(os.Stderr, "usage: agentcage run --agent <path.cage> --target <host>")
		os.Exit(1)
	}

	targets := strings.Split(*target, ",")
	for i := range targets {
		targets[i] = strings.TrimSpace(targets[i])
	}

	req := &pb.CreateAssessmentRequest{
		Config: &pb.AssessmentConfig{
			Scope: &pb.TargetScope{Hosts: targets},
		},
	}
	if *tokenBudget > 0 {
		req.Config.TotalTokenBudget = *tokenBudget
	}
	if *maxDuration != "" {
		d, err := time.ParseDuration(*maxDuration)
		if err != nil {
			fmt.Fprintf(os.Stderr, "invalid duration: %s\n", *maxDuration)
			os.Exit(1)
		}
		req.Config.MaxDuration = durationpb.New(d)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client := pb.NewAssessmentServiceClient(conn)
	resp, err := client.CreateAssessment(ctx, req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error creating assessment: %v\n", err)
		os.Exit(1)
	}

	info := resp.GetAssessment()
	fmt.Printf("Assessment started.\n")
	fmt.Printf("  ID:     %s\n", info.GetAssessmentId())
	fmt.Printf("  Target: %s\n", strings.Join(targets, ", "))
	fmt.Printf("  Agent:  %s\n", *agent)
	fmt.Println("\nUse 'agentcage status' to monitor progress.")
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

func proxyFindings(conn *grpc.ClientConn, args []string) {
	if len(args) > 0 && args[0] == "validate" {
		proxyFindingsValidate(conn, args[1:])
		return
	}
	fmt.Fprintln(os.Stderr, "usage: agentcage findings validate <finding-id> [--vuln-class X] [--proof Y]")
	fmt.Fprintln(os.Stderr, "       agentcage findings list (not yet wired)")
	os.Exit(1)
}

func proxyFindingsValidate(conn *grpc.ClientConn, args []string) {
	fs := flag.NewFlagSet("findings validate", flag.ExitOnError)
	vulnClass := fs.String("vuln-class", "", "override the finding's vuln class")
	proofName := fs.String("proof", "", "specific proof name (defaults to first available)")
	_ = fs.Parse(args)

	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "usage: agentcage findings validate <finding-id> [--vuln-class X] [--proof Y]")
		os.Exit(1)
	}
	findingID := fs.Arg(0)

	client := pb.NewAssessmentServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	resp, err := client.RevalidateFinding(ctx, &pb.RevalidateFindingRequest{
		FindingId: findingID,
		VulnClass: *vulnClass,
		ProofName: *proofName,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Validator cage spawned: %s\n", resp.GetCageId())
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
		fmt.Printf("  %s  cage=%s  %s  %s\n",
			item.GetInterventionId(),
			item.GetCageId(),
			item.GetDescription(),
			item.GetCreatedAt().AsTime().Format(time.RFC3339),
		)
	}
}

func proxyResolve(conn *grpc.ClientConn, args []string) {
	fs := flag.NewFlagSet("resolve", flag.ExitOnError)
	interventionID := fs.String("id", "", "intervention ID")
	action := fs.String("action", "", "action: resume, kill, allow, block")
	rationale := fs.String("rationale", "", "reason for the decision")
	_ = fs.Parse(args)

	if *interventionID == "" || *action == "" {
		fmt.Fprintln(os.Stderr, "usage: agentcage resolve --id <intervention-id> --action <resume|kill|allow|block> [--rationale reason]")
		os.Exit(1)
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

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client := pb.NewInterventionServiceClient(conn)
	_, err := client.ResolveCageIntervention(ctx, &pb.ResolveCageInterventionRequest{
		InterventionId: *interventionID,
		Action:         pbAction,
		Rationale:      *rationale,
	})
	if err != nil {
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
