package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	pb "github.com/okedeji/agentcage/api/proto"
	"github.com/okedeji/agentcage/internal/config"
)

func cmdAudit(args []string) {
	if len(args) < 1 {
		printAuditUsage()
		os.Exit(1)
	}

	switch args[0] {
	case "verify":
		cmdAuditVerify(args[1:])
	case "list":
		cmdAuditList(args[1:])
	case "show":
		cmdAuditShow(args[1:])
	case "export":
		cmdAuditExport(args[1:])
	case "digest":
		cmdAuditDigest(args[1:])
	case "status":
		cmdAuditStatus(args[1:])
	case "keys":
		cmdAuditKeys(args[1:])
	case "validate":
		cmdAuditValidate(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown audit subcommand: %s\n\n", args[0])
		printAuditUsage()
		os.Exit(1)
	}
}

func auditClient() (pb.AuditServiceClient, func(), context.Context) {
	cfg := config.Defaults()
	if resolved := config.Resolve(""); resolved != "" {
		override, err := config.Load(resolved)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: loading config: %v\n", err)
			os.Exit(1)
		}
		cfg = config.Merge(cfg, override)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)

	conn, err := dialOrchestrator(ctx, cfg)
	if err != nil {
		cancel()
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	cleanup := func() {
		_ = conn.Close()
		cancel()
	}

	return pb.NewAuditServiceClient(conn), cleanup, ctx
}

func cmdAuditVerify(args []string) {
	fs := flag.NewFlagSet("audit verify", flag.ExitOnError)
	cageID := fs.String("cage", "", "cage ID to verify")
	assessmentID := fs.String("assessment", "", "verify all cages in assessment")
	_ = fs.Parse(args)

	if *cageID == "" && *assessmentID == "" {
		fmt.Fprintln(os.Stderr, "usage: agentcage audit verify --cage <id> | --assessment <id>")
		os.Exit(1)
	}

	client, cleanup, ctx := auditClient()
	defer cleanup()

	if *cageID != "" {
		verifyOneCage(ctx, client, *cageID)
		return
	}

	resp, err := client.ListCagesWithAudit(ctx, &pb.ListCagesWithAuditRequest{AssessmentId: *assessmentID})
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	if len(resp.GetCageIds()) == 0 {
		fmt.Printf("No audit entries for assessment %s.\n", *assessmentID)
		return
	}

	allPassed := true
	for _, id := range resp.GetCageIds() {
		if !verifyOneCage(ctx, client, id) {
			allPassed = false
		}
	}
	if !allPassed {
		os.Exit(1)
	}
}

func verifyOneCage(ctx context.Context, client pb.AuditServiceClient, cageID string) bool {
	resp, err := client.VerifyChain(ctx, &pb.VerifyChainRequest{CageId: cageID})
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL  %s: %v\n", cageID, err)
		return false
	}
	if !resp.GetValid() {
		fmt.Fprintf(os.Stderr, "FAIL  %s: %s\n", cageID, resp.GetError())
		return false
	}
	fmt.Printf("OK    %s (%d entries)\n", cageID, resp.GetEntryCount())
	return true
}

func cmdAuditList(args []string) {
	fs := flag.NewFlagSet("audit list", flag.ExitOnError)
	cageID := fs.String("cage", "", "cage ID")
	typeFilter := fs.String("type", "", "filter by entry type")
	limit := fs.Int("limit", 0, "max entries to show")
	_ = fs.Parse(args)

	if *cageID == "" {
		fmt.Fprintln(os.Stderr, "usage: agentcage audit list --cage <id> [--type <type>] [--limit N]")
		os.Exit(1)
	}

	client, cleanup, ctx := auditClient()
	defer cleanup()

	resp, err := client.GetEntries(ctx, &pb.GetEntriesRequest{
		CageId:     *cageID,
		TypeFilter: *typeFilter,
		Limit:      int32(*limit),
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	entries := resp.GetEntries()
	if len(entries) == 0 {
		fmt.Println("No audit entries.")
		return
	}

	for _, e := range entries {
		ts := ""
		if e.GetTimestamp() != nil {
			ts = e.GetTimestamp().AsTime().Format(time.RFC3339)
		}
		fmt.Printf("  %4d  %-25s  %s  %s\n", e.GetSequence(), e.GetType(), ts, e.GetId()[:12])
	}
}

func cmdAuditShow(args []string) {
	fs := flag.NewFlagSet("audit show", flag.ExitOnError)
	entryID := fs.String("id", "", "entry ID")
	_ = fs.Parse(args)

	if *entryID == "" {
		fmt.Fprintln(os.Stderr, "usage: agentcage audit show --id <entry-id>")
		os.Exit(1)
	}

	client, cleanup, ctx := auditClient()
	defer cleanup()

	resp, err := client.GetEntry(ctx, &pb.GetEntryRequest{EntryId: *entryID})
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	e := resp.GetEntry()
	fmt.Printf("Entry %s\n", e.GetId())
	fmt.Printf("  Cage:       %s\n", e.GetCageId())
	fmt.Printf("  Assessment: %s\n", e.GetAssessmentId())
	fmt.Printf("  Sequence:   %d\n", e.GetSequence())
	fmt.Printf("  Type:       %s\n", e.GetType())
	if e.GetTimestamp() != nil {
		fmt.Printf("  Timestamp:  %s\n", e.GetTimestamp().AsTime().Format(time.RFC3339))
	}
	fmt.Printf("  KeyVersion: %s\n", e.GetKeyVersion())
	fmt.Printf("  Signature:  %s\n", hex.EncodeToString(e.GetSignature()))
	fmt.Printf("  PrevHash:   %s\n", hex.EncodeToString(e.GetPreviousHash()))
	if len(e.GetData()) > 0 {
		fmt.Printf("\n  Data:\n  %s\n", string(e.GetData()))
	}
}

func cmdAuditExport(args []string) {
	fs := flag.NewFlagSet("audit export", flag.ExitOnError)
	cageID := fs.String("cage", "", "cage ID to export")
	assessmentID := fs.String("assessment", "", "export all cages in assessment")
	output := fs.String("o", "", "write to file instead of stdout")
	_ = fs.Parse(args)

	if *cageID == "" && *assessmentID == "" {
		fmt.Fprintln(os.Stderr, "usage: agentcage audit export --cage <id> [-o file.json]")
		fmt.Fprintln(os.Stderr, "       agentcage audit export --assessment <id> [-o file.json]")
		os.Exit(1)
	}

	client, cleanup, ctx := auditClient()
	defer cleanup()

	var cageIDs []string
	if *cageID != "" {
		cageIDs = []string{*cageID}
	} else {
		resp, err := client.ListCagesWithAudit(ctx, &pb.ListCagesWithAuditRequest{AssessmentId: *assessmentID})
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		cageIDs = resp.GetCageIds()
	}

	var allExports []json.RawMessage
	for _, id := range cageIDs {
		resp, err := client.ExportCage(ctx, &pb.ExportCageRequest{CageId: id})
		if err != nil {
			fmt.Fprintf(os.Stderr, "error exporting cage %s: %v\n", id, err)
			os.Exit(1)
		}
		allExports = append(allExports, resp.GetExportJson())
	}

	var out []byte
	if len(allExports) == 1 {
		out = allExports[0]
	} else {
		var err error
		out, err = json.MarshalIndent(allExports, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	}

	if *output != "" {
		if err := os.WriteFile(*output, out, 0644); err != nil {
			fmt.Fprintf(os.Stderr, "error writing %s: %v\n", *output, err)
			os.Exit(1)
		}
		fmt.Printf("Exported %d cage(s) to %s\n", len(cageIDs), *output)
		return
	}

	fmt.Print(string(out))
}

func cmdAuditDigest(args []string) {
	fs := flag.NewFlagSet("audit digest", flag.ExitOnError)
	cageID := fs.String("cage", "", "cage ID")
	_ = fs.Parse(args)

	if *cageID == "" {
		fmt.Fprintln(os.Stderr, "usage: agentcage audit digest --cage <id>")
		os.Exit(1)
	}

	client, cleanup, ctx := auditClient()
	defer cleanup()

	resp, err := client.GetDigest(ctx, &pb.GetDigestRequest{CageId: *cageID})
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	d := resp.GetDigest()
	if d == nil {
		fmt.Printf("No digest for cage %s.\n", *cageID)
		return
	}

	fmt.Printf("Digest for cage %s\n", d.GetCageId())
	fmt.Printf("  Assessment:    %s\n", d.GetAssessmentId())
	fmt.Printf("  ChainHeadHash: %s\n", hex.EncodeToString(d.GetChainHeadHash()))
	fmt.Printf("  EntryCount:    %d\n", d.GetEntryCount())
	fmt.Printf("  KeyVersion:    %s\n", d.GetKeyVersion())
	fmt.Printf("  Signature:     %s\n", hex.EncodeToString(d.GetSignature()))
	if d.GetIssuedAt() != nil {
		fmt.Printf("  IssuedAt:      %s\n", d.GetIssuedAt().AsTime().Format(time.RFC3339))
	}
}

func cmdAuditStatus(args []string) {
	fs := flag.NewFlagSet("audit status", flag.ExitOnError)
	cageID := fs.String("cage", "", "cage ID")
	_ = fs.Parse(args)

	if *cageID == "" {
		fmt.Fprintln(os.Stderr, "usage: agentcage audit status --cage <id>")
		os.Exit(1)
	}

	client, cleanup, ctx := auditClient()
	defer cleanup()

	resp, err := client.ChainStatus(ctx, &pb.ChainStatusRequest{CageId: *cageID})
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Chain status for cage %s\n", resp.GetCageId())
	fmt.Printf("  Assessment:   %s\n", resp.GetAssessmentId())
	fmt.Printf("  Entries:      %d\n", resp.GetEntryCount())
	if resp.GetFirstTimestamp() != nil {
		fmt.Printf("  First entry:  %s\n", resp.GetFirstTimestamp().AsTime().Format(time.RFC3339))
	}
	if resp.GetLatestTimestamp() != nil {
		fmt.Printf("  Latest entry: %s\n", resp.GetLatestTimestamp().AsTime().Format(time.RFC3339))
	}
	if resp.GetHasDigest() {
		fmt.Printf("  Digest:       yes\n")
	} else {
		fmt.Printf("  Digest:       no\n")
	}
	if len(resp.GetKeyVersions()) > 0 {
		fmt.Printf("  Key versions: %v\n", resp.GetKeyVersions())
	}
}

func cmdAuditKeys(args []string) {
	fs := flag.NewFlagSet("audit keys", flag.ExitOnError)
	cageID := fs.String("cage", "", "cage ID")
	_ = fs.Parse(args)

	if *cageID == "" {
		fmt.Fprintln(os.Stderr, "usage: agentcage audit keys --cage <id>")
		os.Exit(1)
	}

	client, cleanup, ctx := auditClient()
	defer cleanup()

	resp, err := client.GetKeyVersions(ctx, &pb.GetKeyVersionsRequest{CageId: *cageID})
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	versions := resp.GetKeyVersions()
	if len(versions) == 0 {
		fmt.Printf("No key versions found for cage %s.\n", *cageID)
		return
	}

	fmt.Printf("Key versions used in cage %s:\n", *cageID)
	for _, v := range versions {
		fmt.Printf("  %s\n", v)
	}
}

func cmdAuditValidate(args []string) {
	fs := flag.NewFlagSet("audit validate", flag.ExitOnError)
	_ = fs.Parse(args)

	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "usage: agentcage audit validate <export.json>")
		os.Exit(1)
	}

	data, err := os.ReadFile(fs.Arg(0))
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading %s: %v\n", fs.Arg(0), err)
		os.Exit(1)
	}

	var envelope struct {
		CageID       string `json:"cage_id"`
		AssessmentID string `json:"assessment_id"`
		Entries      []struct {
			ID           string `json:"id"`
			Sequence     int64  `json:"sequence"`
			Type         string `json:"type"`
			Timestamp    string `json:"timestamp"`
		} `json:"entries"`
		Digest *struct {
			EntryCount    int64  `json:"entry_count"`
			ChainHeadHash []byte `json:"chain_head_hash"`
		} `json:"digest"`
		ExportedAt string `json:"exported_at"`
	}

	if err := json.Unmarshal(data, &envelope); err != nil {
		fmt.Fprintf(os.Stderr, "FAIL  invalid JSON: %v\n", err)
		os.Exit(1)
	}

	if envelope.CageID == "" {
		fmt.Fprintln(os.Stderr, "FAIL  missing cage_id in export")
		os.Exit(1)
	}
	if len(envelope.Entries) == 0 {
		fmt.Fprintln(os.Stderr, "FAIL  no entries in export")
		os.Exit(1)
	}

	for i, e := range envelope.Entries {
		if e.Sequence != int64(i+1) {
			fmt.Fprintf(os.Stderr, "FAIL  sequence gap at position %d: expected %d, got %d\n", i, i+1, e.Sequence)
			os.Exit(1)
		}
	}

	if envelope.Digest != nil {
		if envelope.Digest.EntryCount != int64(len(envelope.Entries)) {
			fmt.Fprintf(os.Stderr, "FAIL  digest entry_count %d does not match actual entries %d\n",
				envelope.Digest.EntryCount, len(envelope.Entries))
			os.Exit(1)
		}
	}

	fmt.Printf("OK    %s (%d entries", envelope.CageID, len(envelope.Entries))
	if envelope.Digest != nil {
		fmt.Printf(", digest present")
	}
	fmt.Println(")")
}

func printAuditUsage() {
	fmt.Fprintf(os.Stderr, `Usage: agentcage audit <subcommand>

Manage and verify the tamper-evident audit log.

Subcommands:
  verify     Verify audit chain integrity for a cage or assessment
  list       List audit entries for a cage
  show       Show full details of a single audit entry
  export     Export audit log as JSON for external auditors
  digest     Show the latest digest for a cage
  status     Show chain health summary
  keys       List HMAC key versions used in a cage's chain
  validate   Validate an exported audit JSON file offline

Examples:
  agentcage audit verify --cage <cage-id>
  agentcage audit verify --assessment <assessment-id>
  agentcage audit list --cage <cage-id> --type egress_blocked
  agentcage audit show --id <entry-id>
  agentcage audit export --cage <cage-id> -o audit.json
  agentcage audit export --assessment <assessment-id> -o audit.json
  agentcage audit digest --cage <cage-id>
  agentcage audit status --cage <cage-id>
  agentcage audit keys --cage <cage-id>
  agentcage audit validate audit.json
`)
}
