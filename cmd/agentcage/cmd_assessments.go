package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	pb "github.com/okedeji/agentcage/api/proto"
	"github.com/okedeji/agentcage/internal/config"
)

func cmdAssessments(args []string) {
	fs := flag.NewFlagSet("assessments", flag.ExitOnError)
	fs.Usage = printAssessmentsUsage
	id := fs.String("id", "", "assessment ID to show details for")
	statusFilter := fs.String("status", "", "filter by status: discovery, exploitation, validation, pending_review, approved, rejected, failed")
	limit := fs.Int("limit", 50, "max results to return")
	_ = fs.Parse(args)

	cfg := config.Defaults()
	if resolved := config.Resolve(""); resolved != "" {
		override, err := config.Load(resolved)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: loading config: %v\n", err)
			os.Exit(1)
		}
		cfg = config.Merge(cfg, override)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := dialOrchestrator(ctx, cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	defer func() { _ = conn.Close() }()

	client := pb.NewAssessmentServiceClient(conn)

	if *id != "" {
		if *statusFilter != "" {
			fmt.Fprintln(os.Stderr, "error: --status cannot be used with --id")
			os.Exit(1)
		}
		showAssessment(ctx, client, *id)
		return
	}

	listAssessments(ctx, client, *statusFilter, int32(*limit))
}

func showAssessment(ctx context.Context, client pb.AssessmentServiceClient, id string) {
	resp, err := client.GetAssessment(ctx, &pb.GetAssessmentRequest{AssessmentId: id})
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	info := resp.GetAssessment()
	fmt.Printf("Assessment %s\n", info.GetAssessmentId())
	if name := info.GetConfig().GetName(); name != "" {
		fmt.Printf("  Name:     %s\n", name)
	}
	fmt.Printf("  Status:   %s\n", info.GetStatus())
	fmt.Printf("  Customer: %s\n", info.GetCustomerId())
	if scope := info.GetConfig().GetScope(); scope != nil && len(scope.GetHosts()) > 0 {
		fmt.Printf("  Target:   %s\n", strings.Join(scope.GetHosts(), ", "))
	}
	if info.GetCreatedAt() != nil {
		fmt.Printf("  Created:  %s\n", info.GetCreatedAt().AsTime().Format(time.RFC3339))
	}
	if stats := info.GetStats(); stats != nil {
		fmt.Printf("  Cages:    %d total, %d active\n", stats.GetTotalCages(), stats.GetActiveCages())
		fmt.Printf("  Findings: %d candidate, %d validated, %d rejected\n",
			stats.GetFindingsCandidate(), stats.GetFindingsValidated(), stats.GetFindingsRejected())
		fmt.Printf("  Tokens:   %d consumed\n", stats.GetTokensConsumed())
	}
}

func listAssessments(ctx context.Context, client pb.AssessmentServiceClient, statusFilter string, limit int32) {
	req := &pb.ListAssessmentsRequest{Limit: limit}

	if statusFilter != "" {
		s, ok := parseAssessmentStatusFilter(statusFilter)
		if !ok {
			fmt.Fprintf(os.Stderr, "error: unknown status %q (valid: discovery, exploitation, validation, pending_review, approved, rejected, failed)\n", statusFilter)
			os.Exit(1)
		}
		req.StatusFilter = s
	}

	resp, err := client.ListAssessments(ctx, req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	items := resp.GetAssessments()
	if len(items) == 0 {
		if statusFilter != "" {
			fmt.Printf("No %s assessments.\n", statusFilter)
		} else {
			fmt.Println("No assessments.")
		}
		return
	}

	for _, info := range items {
		target := ""
		if scope := info.GetConfig().GetScope(); scope != nil {
			target = strings.Join(scope.GetHosts(), ", ")
		}
		created := ""
		if info.GetCreatedAt() != nil {
			created = info.GetCreatedAt().AsTime().Format(time.RFC3339)
		}
		fmt.Printf("  %s  %-16s  %-15s  %s\n",
			info.GetAssessmentId(),
			info.GetStatus(),
			target,
			created,
		)
	}
}

func parseAssessmentStatusFilter(s string) (pb.AssessmentStatus, bool) {
	switch s {
	case "discovery":
		return pb.AssessmentStatus_ASSESSMENT_STATUS_DISCOVERY, true
	case "exploitation":
		return pb.AssessmentStatus_ASSESSMENT_STATUS_EXPLOITATION, true
	case "validation":
		return pb.AssessmentStatus_ASSESSMENT_STATUS_VALIDATION, true
	case "pending_review":
		return pb.AssessmentStatus_ASSESSMENT_STATUS_PENDING_REVIEW, true
	case "approved":
		return pb.AssessmentStatus_ASSESSMENT_STATUS_APPROVED, true
	case "rejected":
		return pb.AssessmentStatus_ASSESSMENT_STATUS_REJECTED, true
	case "failed":
		return pb.AssessmentStatus_ASSESSMENT_STATUS_FAILED, true
	default:
		return pb.AssessmentStatus_ASSESSMENT_STATUS_UNSPECIFIED, false
	}
}

func printAssessmentsUsage() {
	fmt.Fprintf(os.Stderr, `usage: agentcage assessments [flags]

List assessments or show details for one.

Examples:
  agentcage assessments
  agentcage assessments --status discovery
  agentcage assessments --id <assessment-id>

Flags:
  --id          assessment ID to show details for
  --status      filter by status: discovery, exploitation, validation, pending_review, approved, rejected, failed
  --limit       max results to return (default 50)
`)
}
