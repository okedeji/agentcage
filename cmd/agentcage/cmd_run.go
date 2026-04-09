package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"

	pb "github.com/okedeji/agentcage/api/proto"
	"github.com/okedeji/agentcage/internal/cagefile"
	"github.com/okedeji/agentcage/internal/embedded"
	"github.com/okedeji/agentcage/internal/plan"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	grpcinsecure "google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/durationpb"
)

type stringSliceFlag []string

func (s *stringSliceFlag) String() string     { return strings.Join(*s, ",") }
func (s *stringSliceFlag) Set(v string) error { *s = append(*s, v); return nil }

func cmdRun(args []string) {
	if len(args) == 0 {
		printRunUsage()
		os.Exit(1)
	}

	rf, fs := parseRunFlags(args)
	explicit := explicitFlags(fs)

	p := &plan.Plan{}
	if rf.plan != "" {
		loaded, err := plan.Load(rf.plan)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		p = loaded
	}

	override := plan.FlagsToOverride(explicit, plan.RawFlags{
		Agent:            rf.agent,
		Target:           rf.target,
		Ports:            []string(rf.ports),
		Paths:            []string(rf.paths),
		Exclude:          []string(rf.exclude),
		TokenBudget:      rf.tokenBudget,
		MaxDuration:      rf.maxDuration,
		MaxChainDepth:    rf.maxChainDepth,
		MaxConcurrent:    rf.maxConcurrent,
		Compliance:       []string(rf.compliance),
		Context:          rf.context,
		Focus:            []string(rf.focus),
		Skip:             []string(rf.skip),
		Endpoints:        []string(rf.endpoints),
		APISpecs:         []string(rf.apiSpecs),
		KnownWeaknesses:  []string(rf.knownWeaknesses),
		RequirePoC:       rf.requirePoC,
		HeadlessXSS:      rf.headlessXSS,
		Schedule:         rf.schedule,
		Notify:           rf.notify,
		NotifyOnFinding:  rf.notifyOnFinding,
		NotifyOnComplete: rf.notifyOnComplete,
		Follow:           rf.follow,
		Format:           rf.format,
		Name:             rf.name,
		Tags:             []string(rf.tags),
		CustomerID:       rf.customerID,
	})
	p = plan.Merge(p, override)

	plan.ApplyDefaults(p)
	if err := plan.Validate(p); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	if p.Schedule.Mode == "cron" || p.Schedule.Mode == "on_push" {
		fmt.Fprintf(os.Stderr, "scheduled assessments are not yet supported (schedule.mode=%s)\n", p.Schedule.Mode)
		os.Exit(1)
	}

	bundleRef, err := prepareBundle(p.Agent)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	conn, err := dialOrchestrator()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	defer func() { _ = conn.Close() }()

	req := buildCreateAssessmentRequest(p, bundleRef)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	client := pb.NewAssessmentServiceClient(conn)
	resp, err := client.CreateAssessment(ctx, req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error creating assessment: %v\n", err)
		os.Exit(1)
	}

	info := resp.GetAssessment()
	printAssessmentSummary(info, p, bundleRef)

	if p.Output.Follow {
		followAssessment(conn, info.GetAssessmentId(), p.Output.Format)
	}
}

func prepareBundle(agentPath string) (string, error) {
	fi, err := os.Stat(agentPath)
	if err != nil {
		return "", fmt.Errorf("agent path %s: %w", agentPath, err)
	}

	storeDir := filepath.Join(embedded.DataDir(), "bundles")
	store, err := cagefile.NewBundleStore(storeDir)
	if err != nil {
		return "", err
	}

	if fi.IsDir() {
		fmt.Println("Packing agent directory...")
		ref, packErr := store.PackAndStore(agentPath, version, 0)
		if packErr != nil {
			return "", fmt.Errorf("packing agent: %w", packErr)
		}
		return ref, nil
	}

	if !strings.HasSuffix(agentPath, ".cage") {
		return "", fmt.Errorf("agent file %s does not have a .cage extension (use 'agentcage pack <dir>' to create one, or pass a directory to --agent)", agentPath)
	}

	fmt.Println("Verifying bundle...")
	tmpDir, tmpErr := os.MkdirTemp("", "agentcage-verify-*")
	if tmpErr != nil {
		return "", fmt.Errorf("creating temp dir for verify: %w", tmpErr)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	manifest, unpackErr := cagefile.UnpackFile(agentPath, tmpDir)
	if unpackErr != nil {
		return "", fmt.Errorf("verifying bundle %s: %w", agentPath, unpackErr)
	}
	if err := cagefile.CheckCompatibility(manifest, version); err != nil {
		return "", err
	}

	ref, storeErr := store.Store(agentPath)
	if storeErr != nil {
		return "", fmt.Errorf("storing bundle: %w", storeErr)
	}
	return ref, nil
}

func dialOrchestrator() (*grpc.ClientConn, error) {
	addr := os.Getenv("AGENTCAGE_GRPC_ADDR")
	if addr == "" {
		addr = "localhost:9090"
	}

	creds, err := buildClientCredentials()
	if err != nil {
		return nil, fmt.Errorf("building TLS credentials: %w", err)
	}

	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(creds))
	if err != nil {
		return nil, fmt.Errorf("connecting to orchestrator at %s: %w", addr, err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	control := pb.NewControlServiceClient(conn)
	if _, err := control.Ping(ctx, &pb.PingRequest{}); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("orchestrator not reachable at %s (run 'agentcage init' first): %w", addr, err)
	}
	return conn, nil
}

// AGENTCAGE_TLS_CERT and AGENTCAGE_TLS_KEY enable mTLS.
// AGENTCAGE_TLS_CA pins the server CA. Without any of these the
// connection is plaintext, which is fine for localhost/dev.
func buildClientCredentials() (credentials.TransportCredentials, error) {
	certFile := os.Getenv("AGENTCAGE_TLS_CERT")
	keyFile := os.Getenv("AGENTCAGE_TLS_KEY")
	caFile := os.Getenv("AGENTCAGE_TLS_CA")

	if certFile == "" && keyFile == "" && caFile == "" {
		return grpcinsecure.NewCredentials(), nil
	}

	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}

	if certFile != "" && keyFile != "" {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, fmt.Errorf("loading client cert %s: %w", certFile, err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}

	if caFile != "" {
		ca, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("reading CA file %s: %w", caFile, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(ca) {
			return nil, fmt.Errorf("CA file %s: no PEM certs found", caFile)
		}
		tlsCfg.RootCAs = pool
	}

	return credentials.NewTLS(tlsCfg), nil
}

func buildCreateAssessmentRequest(p *plan.Plan, bundleRef string) *pb.CreateAssessmentRequest {
	cfg := &pb.AssessmentConfig{
		Name:               p.Name,
		CustomerId:         p.CustomerID,
		TotalTokenBudget:   p.Budget.Tokens,
		MaxChainDepth:      p.Limits.MaxChainDepth,
		MaxConcurrentCages: p.Limits.MaxConcurrentCages,
		ExcludeHosts:       excludeHosts(p.Target.Exclude),
		ExcludePaths:       excludePaths(p.Target.Exclude),
		Tags:               p.Tags,
	}

	cfg.Scope = &pb.TargetScope{
		Hosts: p.Target.Hosts,
		Ports: p.Target.Ports,
		Paths: p.Target.Paths,
	}

	if p.Budget.MaxDuration != "" {
		d, _ := time.ParseDuration(p.Budget.MaxDuration)
		cfg.MaxDuration = durationpb.New(d)
	}

	for _, c := range p.Limits.Compliance {
		cfg.Compliance = append(cfg.Compliance, complianceToProto(c))
	}

	for name, ct := range p.CageTypes {
		ctPb := &pb.CageTypeConfig{
			Type:          cageTypeNameToProto(name),
			MaxConcurrent: ct.MaxConcurrent,
			Defaults:      &pb.ResourceLimits{Vcpus: ct.VCPUs, MemoryMb: ct.MemoryMB},
		}
		if ct.MaxDuration != "" {
			d, _ := time.ParseDuration(ct.MaxDuration)
			ctPb.MaxDuration = durationpb.New(d)
		}
		cfg.CageTypeConfigs = append(cfg.CageTypeConfigs, ctPb)
	}

	cfg.Guidance = buildGuidanceProto(p)

	if p.Notifications.Webhook != "" || p.Notifications.OnFinding || p.Notifications.OnComplete {
		cfg.Notifications = &pb.NotificationConfig{
			Webhook:    p.Notifications.Webhook,
			OnFinding:  p.Notifications.OnFinding,
			OnComplete: p.Notifications.OnComplete,
		}
	}

	return &pb.CreateAssessmentRequest{
		Config:    cfg,
		BundleRef: bundleRef,
	}
}

func buildGuidanceProto(p *plan.Plan) *pb.Guidance {
	g := &pb.Guidance{}
	hasContent := false

	if len(p.Guidance.AttackSurface.Endpoints) > 0 || len(p.Guidance.AttackSurface.APISpecs) > 0 || p.Guidance.AttackSurface.LimitToListed {
		g.AttackSurface = &pb.AttackSurfaceGuidance{
			Endpoints:     p.Guidance.AttackSurface.Endpoints,
			ApiSpecs:      p.Guidance.AttackSurface.APISpecs,
			LimitToListed: p.Guidance.AttackSurface.LimitToListed,
		}
		hasContent = true
	}

	if len(p.Guidance.Priorities.VulnClasses) > 0 || len(p.Guidance.Priorities.SkipPaths) > 0 {
		g.Priorities = &pb.PrioritiesGuidance{
			VulnClasses: p.Guidance.Priorities.VulnClasses,
			SkipPaths:   p.Guidance.Priorities.SkipPaths,
		}
		hasContent = true
	}

	if p.Guidance.Strategy.Context != "" || len(p.Guidance.Strategy.KnownWeaknesses) > 0 {
		g.AttackStrategy = &pb.AttackStrategyGuidance{
			Context:         p.Guidance.Strategy.Context,
			KnownWeaknesses: p.Guidance.Strategy.KnownWeaknesses,
		}
		hasContent = true
	}

	if p.Guidance.Validation.RequirePoC || p.Guidance.Validation.HeadlessBrowserXSS {
		g.Validation = &pb.ValidationGuidance{
			RequirePoc:         p.Guidance.Validation.RequirePoC,
			HeadlessBrowserXss: p.Guidance.Validation.HeadlessBrowserXSS,
		}
		hasContent = true
	}

	if !hasContent {
		return nil
	}
	return g
}

func printAssessmentSummary(info *pb.AssessmentInfo, p *plan.Plan, bundleRef string) {
	fmt.Println("\nAssessment started.")
	fmt.Printf("  ID:         %s\n", info.GetAssessmentId())
	if p.Name != "" {
		fmt.Printf("  Name:       %s\n", p.Name)
	}
	fmt.Printf("  Agent:      %s (sha256:%s)\n", p.Agent, bundleRef[:12])
	fmt.Printf("  Target:     %s\n", strings.Join(p.Target.Hosts, ", "))
	if p.Budget.Tokens > 0 || p.Budget.MaxDuration != "" {
		parts := []string{}
		if p.Budget.Tokens > 0 {
			parts = append(parts, fmt.Sprintf("%d tokens", p.Budget.Tokens))
		}
		if p.Budget.MaxDuration != "" {
			parts = append(parts, p.Budget.MaxDuration)
		}
		fmt.Printf("  Budget:     %s\n", strings.Join(parts, " / "))
	}
	if len(p.Limits.Compliance) > 0 {
		fmt.Printf("  Compliance: %s\n", strings.Join(p.Limits.Compliance, ", "))
	}
	if p.Limits.MaxConcurrentCages > 0 {
		fmt.Printf("  Cages:      up to %d concurrent\n", p.Limits.MaxConcurrentCages)
	}
	if !p.Output.Follow {
		fmt.Printf("\nUse 'agentcage status --assessment %s' to monitor.\n", info.GetAssessmentId())
	}
}

func followAssessment(conn *grpc.ClientConn, assessmentID, format string) {
	sigCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	client := pb.NewAssessmentServiceClient(conn)
	jsonMode := format == "json"
	var lastStatus string
	var lastFindings int32
	var lastCages int32

	fmt.Println("\nFollowing assessment progress... (Ctrl+C to detach, assessment continues)")

	for {
		pollCtx, cancel := context.WithTimeout(sigCtx, 5*time.Second)
		resp, err := client.GetAssessment(pollCtx, &pb.GetAssessmentRequest{AssessmentId: assessmentID})
		cancel()

		if sigCtx.Err() != nil {
			fmt.Printf("\nDetached. Assessment %s continues on the server.\n", assessmentID)
			fmt.Printf("Run 'agentcage status --assessment %s' to check progress.\n", assessmentID)
			return
		}

		if err != nil {
			fmt.Fprintf(os.Stderr, "  poll error: %v\n", err)
			time.Sleep(3 * time.Second)
			continue
		}

		info := resp.GetAssessment()
		status := info.GetStatus().String()
		stats := info.GetStats()

		if status != lastStatus {
			if jsonMode {
				fmt.Printf("{\"phase\":%q,\"assessment_id\":%q}\n", status, assessmentID)
			} else {
				fmt.Printf("  Phase: %s\n", status)
			}
			lastStatus = status
		}

		if stats != nil {
			if stats.GetActiveCages() != lastCages {
				lastCages = stats.GetActiveCages()
				if !jsonMode {
					fmt.Printf("  Cages: %d active, %d total\n", lastCages, stats.GetTotalCages())
				}
			}

			validated := stats.GetFindingsValidated()
			candidate := stats.GetFindingsCandidate()
			if validated != lastFindings || (candidate > 0 && lastFindings == 0) {
				if jsonMode {
					fmt.Printf("{\"findings_candidate\":%d,\"findings_validated\":%d,\"findings_rejected\":%d,\"tokens_consumed\":%d}\n",
						candidate, validated, stats.GetFindingsRejected(), stats.GetTokensConsumed())
				} else {
					fmt.Printf("  Findings: %d candidate, %d validated, %d rejected\n",
						candidate, validated, stats.GetFindingsRejected())
				}
				lastFindings = validated
			}
		}

		switch info.GetStatus() {
		case pb.AssessmentStatus_ASSESSMENT_STATUS_APPROVED:
			var v int32
			if stats != nil {
				v = stats.GetFindingsValidated()
			}
			if jsonMode {
				fmt.Printf("{\"result\":\"approved\",\"findings_validated\":%d}\n", v)
			} else {
				fmt.Printf("\nAssessment approved. %d validated findings.\n", v)
				fmt.Printf("Run 'agentcage report --assessment %s' for full report.\n", assessmentID)
			}
			return
		case pb.AssessmentStatus_ASSESSMENT_STATUS_REJECTED:
			if jsonMode {
				fmt.Printf("{\"result\":\"rejected\"}\n")
			} else {
				fmt.Printf("\nAssessment rejected.\n")
				fmt.Printf("Run 'agentcage report --assessment %s' for details.\n", assessmentID)
			}
			return
		}

		time.Sleep(3 * time.Second)
	}
}

func excludeHosts(exclude []string) []string {
	var out []string
	for _, e := range exclude {
		if !strings.HasPrefix(e, "/") {
			out = append(out, e)
		}
	}
	return out
}

func excludePaths(exclude []string) []string {
	var out []string
	for _, e := range exclude {
		if strings.HasPrefix(e, "/") {
			out = append(out, e)
		}
	}
	return out
}

func complianceToProto(c string) pb.ComplianceFramework {
	switch strings.ToLower(c) {
	case "soc2":
		return pb.ComplianceFramework_COMPLIANCE_FRAMEWORK_SOC2
	case "hipaa":
		return pb.ComplianceFramework_COMPLIANCE_FRAMEWORK_HIPAA
	case "pci_dss":
		return pb.ComplianceFramework_COMPLIANCE_FRAMEWORK_PCI_DSS
	default:
		return pb.ComplianceFramework_COMPLIANCE_FRAMEWORK_UNSPECIFIED
	}
}

func cageTypeNameToProto(name string) pb.CageType {
	switch name {
	case "discovery":
		return pb.CageType_CAGE_TYPE_DISCOVERY
	case "validator":
		return pb.CageType_CAGE_TYPE_VALIDATOR
	case "escalation":
		return pb.CageType_CAGE_TYPE_ESCALATION
	default:
		return pb.CageType_CAGE_TYPE_UNSPECIFIED
	}
}

// parseRunFlags and helpers live in cmd because they're CLI wiring.

func parseRunFlags(args []string) (*runFlags, *flag.FlagSet) {
	rf := &runFlags{}
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	fs.Usage = printRunUsage

	fs.StringVar(&rf.plan, "plan", "", "path to assessment YAML plan file")
	fs.StringVar(&rf.agent, "agent", "", "path to .cage bundle or agent directory")
	fs.StringVar(&rf.target, "target", "", "target host(s), comma-separated")
	fs.Var(&rf.ports, "port", "port to include (repeatable)")
	fs.Var(&rf.paths, "path", "URL path to scope (repeatable)")
	fs.Var(&rf.exclude, "exclude", "host or path to exclude (repeatable)")
	fs.Int64Var(&rf.tokenBudget, "token-budget", 0, "LLM token cap")
	fs.StringVar(&rf.maxDuration, "max-duration", "", "assessment wall clock (e.g. 30m, 4h)")
	fs.IntVar(&rf.maxChainDepth, "max-chain-depth", 0, "escalation chain depth limit")
	fs.IntVar(&rf.maxConcurrent, "max-concurrent", 0, "max concurrent cages")
	fs.Var(&rf.compliance, "compliance", "compliance framework (repeatable: soc2, hipaa, pci_dss)")
	fs.StringVar(&rf.context, "context", "", "free-text context for the LLM coordinator")
	fs.Var(&rf.focus, "focus", "vuln class to prioritize (repeatable)")
	fs.Var(&rf.skip, "skip", "path to deprioritize (repeatable)")
	fs.Var(&rf.endpoints, "endpoint", "endpoint to focus on (repeatable)")
	fs.Var(&rf.apiSpecs, "api-spec", "OpenAPI/GraphQL spec URL (repeatable)")
	fs.Var(&rf.knownWeaknesses, "known-weakness", "known weakness hint (repeatable)")
	fs.BoolVar(&rf.requirePoC, "require-poc", false, "require PoC for every finding")
	fs.BoolVar(&rf.headlessXSS, "headless-xss", false, "headless browser for XSS validation")
	fs.StringVar(&rf.schedule, "schedule", "once", "\"once\" (default) or cron expression")
	fs.StringVar(&rf.notify, "notify", "", "webhook URL for notifications")
	fs.BoolVar(&rf.notifyOnFinding, "notify-on-finding", false, "notify per validated finding")
	fs.BoolVar(&rf.notifyOnComplete, "notify-on-complete", false, "notify when assessment finishes")
	fs.BoolVar(&rf.follow, "follow", false, "stream status updates until terminal state")
	fs.StringVar(&rf.format, "format", "text", "output format: text, json")
	fs.StringVar(&rf.name, "name", "", "human name for this assessment")
	fs.Var(&rf.tags, "tag", "key=value metadata (repeatable)")
	fs.StringVar(&rf.customerID, "customer-id", "", "customer identifier")

	_ = fs.Parse(args)
	return rf, fs
}

type runFlags struct {
	plan             string
	agent            string
	target           string
	ports            stringSliceFlag
	paths            stringSliceFlag
	exclude          stringSliceFlag
	tokenBudget      int64
	maxDuration      string
	maxChainDepth    int
	maxConcurrent    int
	compliance       stringSliceFlag
	context          string
	focus            stringSliceFlag
	skip             stringSliceFlag
	endpoints        stringSliceFlag
	apiSpecs         stringSliceFlag
	knownWeaknesses  stringSliceFlag
	requirePoC       bool
	headlessXSS      bool
	schedule         string
	notify           string
	notifyOnFinding  bool
	notifyOnComplete bool
	follow           bool
	format           string
	name             string
	tags             stringSliceFlag
	customerID       string
}

func explicitFlags(fs *flag.FlagSet) map[string]bool {
	m := make(map[string]bool)
	fs.Visit(func(f *flag.Flag) {
		m[f.Name] = true
	})
	return m
}

func printRunUsage() {
	fmt.Fprintf(os.Stderr, `usage: agentcage run --agent <path> --target <host> [flags]
       agentcage run --plan <assessment.yaml> [flag overrides]

Examples:
  agentcage run --agent ./my-agent.cage --target example.com
  agentcage run --plan plans/staging.yaml --follow
  agentcage run --agent ./agent/ --target api.example.com --focus sqli --require-poc

Required (unless in plan file):
  --agent              .cage file or agent directory
  --target             target host(s), comma-separated

Plan file:
  --plan               path to assessment YAML plan file

Target scoping:
  --port               port to include (repeatable)
  --path               URL path to scope (repeatable)
  --exclude            host or path to exclude (repeatable)

Budget & limits:
  --token-budget       LLM token cap
  --max-duration       assessment wall clock (e.g. 30m, 4h)
  --max-chain-depth    escalation chain depth limit
  --max-concurrent     max concurrent cages
  --compliance         compliance framework (repeatable: soc2, hipaa, pci_dss)

Guidance:
  --context            free-text context for the LLM coordinator
  --focus              vuln class to prioritize (repeatable)
  --skip               path to deprioritize (repeatable)
  --endpoint           endpoint to focus on (repeatable)
  --api-spec           OpenAPI/GraphQL spec URL (repeatable)
  --known-weakness     known weakness hint (repeatable)
  --require-poc        require PoC for every finding
  --headless-xss       headless browser for XSS validation

Scheduling:
  --schedule           "once" (default) or cron expression

Notifications:
  --notify             webhook URL for notifications
  --notify-on-finding  notify per validated finding
  --notify-on-complete notify when assessment finishes

Output:
  --follow             stream status updates until terminal state
  --format             output format: text, json
  --name               human name for this assessment
  --tag                key=value metadata (repeatable)
  --customer-id        customer identifier
`)
}
