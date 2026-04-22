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

func cmdFindings(args []string) {
	if len(args) > 0 && args[0] == "delete" {
		cmdFindingsDelete(args[1:])
		return
	}

	fs := flag.NewFlagSet("findings", flag.ExitOnError)
	fs.Usage = printFindingsUsage
	assessmentID := fs.String("assessment", "", "assessment ID (required for listing)")
	findingID := fs.String("id", "", "finding ID to show details for")
	statusFilter := fs.String("status", "", "filter by status: candidate, validated, rejected")
	severity := fs.String("severity", "", "filter by severity: critical, high, medium, low, info")
	limit := fs.Int("limit", 100, "max results to return")
	_ = fs.Parse(args)

	if *findingID == "" && *assessmentID == "" {
		fmt.Fprintln(os.Stderr, "error: --assessment or --id is required")
		printFindingsUsage()
		os.Exit(1)
	}

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

	client := pb.NewFindingsServiceClient(conn)

	if *findingID != "" {
		if *assessmentID != "" || *statusFilter != "" || *severity != "" {
			fmt.Fprintln(os.Stderr, "error: --id cannot be combined with --assessment, --status, or --severity")
			os.Exit(1)
		}
		showFinding(ctx, client, *findingID)
		return
	}

	listFindings(ctx, client, *assessmentID, *statusFilter, *severity, int32(*limit))
}

func cmdFindingsDelete(args []string) {
	fs := flag.NewFlagSet("findings delete", flag.ExitOnError)
	assessmentID := fs.String("assessment", "", "delete all findings for an assessment")
	findingID := fs.String("id", "", "delete a single finding by ID")
	_ = fs.Parse(args)

	if *assessmentID == "" && *findingID == "" {
		fmt.Fprintln(os.Stderr, "usage: agentcage findings delete --id <finding-id>")
		fmt.Fprintln(os.Stderr, "       agentcage findings delete --assessment <assessment-id>")
		os.Exit(1)
	}
	if *assessmentID != "" && *findingID != "" {
		fmt.Fprintln(os.Stderr, "error: --assessment and --id cannot be used together")
		os.Exit(1)
	}

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

	client := pb.NewFindingsServiceClient(conn)

	if *findingID != "" {
		if _, err := client.DeleteFinding(ctx, &pb.DeleteFindingRequest{FindingId: *findingID}); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Finding %s deleted.\n", *findingID)
		return
	}

	resp, err := client.DeleteByAssessment(ctx, &pb.DeleteByAssessmentRequest{AssessmentId: *assessmentID})
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Deleted %d findings for assessment %s.\n", resp.GetDeleted(), *assessmentID)
}

func showFinding(ctx context.Context, client pb.FindingsServiceClient, id string) {
	resp, err := client.GetFinding(ctx, &pb.GetFindingRequest{FindingId: id})
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	f := resp.GetFinding()
	fmt.Printf("Finding %s\n", f.GetFindingId())
	fmt.Printf("  Title:      %s\n", f.GetTitle())
	fmt.Printf("  Status:     %s\n", f.GetStatus())
	fmt.Printf("  Severity:   %s\n", f.GetSeverity())
	fmt.Printf("  VulnClass:  %s\n", f.GetVulnClass())
	if f.GetEndpoint() != "" {
		fmt.Printf("  Endpoint:   %s\n", f.GetEndpoint())
	}
	fmt.Printf("  Assessment: %s\n", f.GetAssessmentId())
	fmt.Printf("  Cage:       %s\n", f.GetCageId())
	if f.GetChainDepth() > 0 {
		fmt.Printf("  Chain:      depth %d", f.GetChainDepth())
		if f.GetParentFindingId() != "" {
			fmt.Printf(" (parent: %s)", f.GetParentFindingId())
		}
		fmt.Println()
	}
	if f.GetCwe() != "" {
		fmt.Printf("  CWE:        %s\n", f.GetCwe())
	}
	if f.GetCvssScore() > 0 {
		fmt.Printf("  CVSS:       %.1f\n", f.GetCvssScore())
	}
	if f.GetCreatedAt() != nil {
		fmt.Printf("  Created:    %s\n", f.GetCreatedAt().AsTime().Format(time.RFC3339))
	}
	if f.GetValidatedAt() != nil {
		fmt.Printf("  Validated:  %s\n", f.GetValidatedAt().AsTime().Format(time.RFC3339))
	}
	if f.GetDescription() != "" {
		fmt.Printf("\n  %s\n", f.GetDescription())
	}
	if f.GetRemediation() != "" {
		fmt.Printf("\n  Remediation:\n  %s\n", f.GetRemediation())
	}
	if ev := f.GetEvidence(); ev != nil && ev.GetPoc() != "" {
		fmt.Printf("\n  PoC:\n  %s\n", ev.GetPoc())
	}
	if vp := f.GetValidationProof(); vp != nil && vp.GetConfirmed() {
		fmt.Printf("\n  Validation Proof:\n")
		fmt.Printf("    Confirmed by cage %s\n", vp.GetValidatorCageId())
		if vp.GetReproductionSteps() != "" {
			fmt.Printf("    Steps: %s\n", vp.GetReproductionSteps())
		}
		fmt.Printf("    Deterministic: %v\n", vp.GetDeterministic())
	}
}

func listFindings(ctx context.Context, client pb.FindingsServiceClient, assessmentID, statusFilter, severityFilter string, limit int32) {
	req := &pb.ListFindingsRequest{
		AssessmentId: assessmentID,
		Limit:        limit,
	}

	if statusFilter != "" {
		s, ok := parseFindingStatusFilter(statusFilter)
		if !ok {
			fmt.Fprintf(os.Stderr, "error: unknown status %q (valid: candidate, validated, rejected)\n", statusFilter)
			os.Exit(1)
		}
		req.StatusFilter = s
	}

	if severityFilter != "" {
		s, ok := parseFindingSeverityFilter(severityFilter)
		if !ok {
			fmt.Fprintf(os.Stderr, "error: unknown severity %q (valid: critical, high, medium, low, info)\n", severityFilter)
			os.Exit(1)
		}
		req.SeverityFilter = s
	}

	resp, err := client.ListFindings(ctx, req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	items := resp.GetFindings()
	if len(items) == 0 {
		fmt.Println("No findings.")
		return
	}

	for _, f := range items {
		created := ""
		if f.GetCreatedAt() != nil {
			created = f.GetCreatedAt().AsTime().Format(time.RFC3339)
		}
		fmt.Printf("  %s  %-10s  %-9s  %-15s  %s  %s\n",
			f.GetFindingId(),
			f.GetStatus(),
			f.GetSeverity(),
			f.GetVulnClass(),
			truncate(f.GetTitle(), 50),
			created,
		)
	}
}

func truncate(s string, max int) string {
	runes := []rune(s)
	if len(runes) <= max {
		return s
	}
	if max <= 3 {
		return string(runes[:max])
	}
	return string(runes[:max-3]) + "..."
}

func parseFindingStatusFilter(s string) (pb.FindingStatus, bool) {
	switch strings.ToLower(s) {
	case "candidate":
		return pb.FindingStatus_FINDING_STATUS_CANDIDATE, true
	case "validated":
		return pb.FindingStatus_FINDING_STATUS_VALIDATED, true
	case "rejected":
		return pb.FindingStatus_FINDING_STATUS_REJECTED, true
	default:
		return pb.FindingStatus_FINDING_STATUS_UNSPECIFIED, false
	}
}

func parseFindingSeverityFilter(s string) (pb.FindingSeverity, bool) {
	switch strings.ToLower(s) {
	case "info":
		return pb.FindingSeverity_FINDING_SEVERITY_INFO, true
	case "low":
		return pb.FindingSeverity_FINDING_SEVERITY_LOW, true
	case "medium":
		return pb.FindingSeverity_FINDING_SEVERITY_MEDIUM, true
	case "high":
		return pb.FindingSeverity_FINDING_SEVERITY_HIGH, true
	case "critical":
		return pb.FindingSeverity_FINDING_SEVERITY_CRITICAL, true
	default:
		return pb.FindingSeverity_FINDING_SEVERITY_UNSPECIFIED, false
	}
}

func printFindingsUsage() {
	fmt.Fprintf(os.Stderr, `usage: agentcage findings --assessment <id> [flags]
       agentcage findings --id <finding-id>
       agentcage findings delete --id <finding-id>
       agentcage findings delete --assessment <assessment-id>

List findings for an assessment, show details for one, or delete.

Examples:
  agentcage findings --assessment <assessment-id>
  agentcage findings --assessment <assessment-id> --severity critical
  agentcage findings --assessment <assessment-id> --status validated
  agentcage findings --id <finding-id>
  agentcage findings delete --id <finding-id>
  agentcage findings delete --assessment <assessment-id>

Flags:
  --assessment   assessment ID (required for listing or bulk delete)
  --id           finding ID to show details for or delete
  --status       filter by status: candidate, validated, rejected
  --severity     filter by severity: critical, high, medium, low, info
  --limit        max results to return (default 100)
`)
}
