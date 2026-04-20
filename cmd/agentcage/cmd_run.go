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
	"github.com/okedeji/agentcage/internal/config"
	agentgrpc "github.com/okedeji/agentcage/internal/grpc"
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

	cfg := config.Defaults()
	if resolved := config.Resolve(""); resolved != "" {
		override, loadErr := config.Load(resolved)
		if loadErr != nil {
			fmt.Fprintf(os.Stderr, "error loading operator config: %v\n", loadErr)
			os.Exit(1)
		}
		cfg = config.Merge(cfg, override)
	}

	p := plan.BasePlanFromConfig(cfg)
	if rf.plan != "" {
		loaded, err := plan.Load(rf.plan)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		p = plan.Merge(p, loaded)
	}

	override := plan.FlagsToOverride(explicit, plan.RawFlags{
		Agent:            rf.agent,
		Target:           rf.target,
		Ports:            []string(rf.ports),
		Paths:            []string(rf.paths),
		SkipPaths:        []string(rf.skipPaths),
		TokenBudget:      rf.tokenBudget,
		MaxDuration:      rf.maxDuration,
		MaxChainDepth:    rf.maxChainDepth,
		MaxConcurrent:    rf.maxConcurrent,
		MaxIterations:    rf.maxIterations,
		Context:          rf.context,
		Focus:            []string(rf.focus),
		Skip:             []string(rf.skip),
		Endpoints:        []string(rf.endpoints),
		APISpecs:         []string(rf.apiSpecs),
		KnownWeaknesses:  []string(rf.knownWeaknesses),
		RequirePoC:       rf.requirePoC,
		HeadlessXSS:      rf.headlessXSS,
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
	if err := plan.EnforceConfigCeilings(p, cfg); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	bundleRef, err := prepareBundle(p.Agent)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	conn, err := dialOrchestrator(cfg)
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

	if plan.BoolVal(p.Output.Follow) {
		followAssessment(conn, info.GetAssessmentId(), p.Output.Format)
	}
}

func prepareBundle(agentPath string) (string, error) {
	fi, err := os.Stat(agentPath)
	if err != nil {
		return "", fmt.Errorf("agent path %s: %w", agentPath, err)
	}
	if fi.IsDir() {
		return "", fmt.Errorf("agent path %s is a directory, not a .cage bundle (run 'agentcage pack %s' first)", agentPath, agentPath)
	}
	if !strings.HasSuffix(agentPath, ".cage") {
		return "", fmt.Errorf("agent file %s does not have a .cage extension (run 'agentcage pack <dir>' to create one)", agentPath)
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

	storeDir := filepath.Join(embedded.DataDir(), "bundles")
	store, err := cagefile.NewBundleStore(storeDir)
	if err != nil {
		return "", err
	}

	ref, storeErr := store.Store(agentPath)
	if storeErr != nil {
		return "", fmt.Errorf("storing bundle: %w", storeErr)
	}
	return ref, nil
}

func dialOrchestrator(cfg *config.Config) (*grpc.ClientConn, error) {
	addr := cfg.ServerAddress()

	creds, err := buildClientCredentials(cfg)
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

// Plaintext when no TLS is configured, which is fine for localhost/dev.
// Configure via `agentcage login` or the server.tls section in config.
func buildClientCredentials(cfg *config.Config) (credentials.TransportCredentials, error) {
	t := cfg.Server.TLS
	if cfg.Server.Insecure || t == nil {
		return grpcinsecure.NewCredentials(), nil
	}

	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12, CipherSuites: agentgrpc.PreferredCipherSuites}

	if t.CertFile != "" && t.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(t.CertFile, t.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("loading client cert %s: %w", t.CertFile, err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}

	if t.CAFile != "" {
		ca, err := os.ReadFile(t.CAFile)
		if err != nil {
			return nil, fmt.Errorf("reading CA file %s: %w", t.CAFile, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(ca) {
			return nil, fmt.Errorf("CA file %s: no PEM certs found", t.CAFile)
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
		SkipPaths:          p.Target.SkipPaths,
		Tags:               p.Tags,
	}

	if p.Limits.MaxIterations > 0 {
		cfg.MaxIterations = p.Limits.MaxIterations
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

	if p.Notifications.Webhook != "" || plan.BoolVal(p.Notifications.OnFinding) || plan.BoolVal(p.Notifications.OnComplete) {
		cfg.Notifications = &pb.NotificationConfig{
			Webhook:    p.Notifications.Webhook,
			OnFinding:  plan.BoolVal(p.Notifications.OnFinding),
			OnComplete: plan.BoolVal(p.Notifications.OnComplete),
		}
	}

	for _, p := range p.Payload.ExtraBlock {
		cfg.ExtraBlock = append(cfg.ExtraBlock, &pb.PatternEntry{Pattern: p.Pattern, Reason: p.Reason})
	}
	for _, p := range p.Payload.ExtraFlag {
		cfg.ExtraFlag = append(cfg.ExtraFlag, &pb.PatternEntry{Pattern: p.Pattern, Reason: p.Reason})
	}

	return &pb.CreateAssessmentRequest{
		Config:    cfg,
		BundleRef: bundleRef,
	}
}

func buildGuidanceProto(p *plan.Plan) *pb.Guidance {
	g := &pb.Guidance{}
	hasContent := false

	if len(p.Guidance.AttackSurface.Endpoints) > 0 || len(p.Guidance.AttackSurface.APISpecs) > 0 || plan.BoolVal(p.Guidance.AttackSurface.LimitToListed) {
		g.AttackSurface = &pb.AttackSurfaceGuidance{
			Endpoints:     p.Guidance.AttackSurface.Endpoints,
			ApiSpecs:      p.Guidance.AttackSurface.APISpecs,
			LimitToListed: plan.BoolVal(p.Guidance.AttackSurface.LimitToListed),
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

	if plan.BoolVal(p.Guidance.Validation.RequirePoC) || plan.BoolVal(p.Guidance.Validation.HeadlessBrowserXSS) {
		g.Validation = &pb.ValidationGuidance{
			RequirePoc:         plan.BoolVal(p.Guidance.Validation.RequirePoC),
			HeadlessBrowserXss: plan.BoolVal(p.Guidance.Validation.HeadlessBrowserXSS),
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
	if p.Limits.MaxConcurrentCages > 0 {
		fmt.Printf("  Cages:      up to %d concurrent\n", p.Limits.MaxConcurrentCages)
	}
	if !plan.BoolVal(p.Output.Follow) {
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

func parseRunFlags(args []string) (*runFlags, *flag.FlagSet) {
	rf := &runFlags{}
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	fs.Usage = printRunUsage

	fs.StringVar(&rf.plan, "plan", "", "path to assessment YAML plan file")
	fs.StringVar(&rf.agent, "agent", "", "path to .cage bundle")
	fs.StringVar(&rf.target, "target", "", "target host(s), comma-separated")
	fs.Var(&rf.ports, "port", "port to include (repeatable)")
	fs.Var(&rf.paths, "path", "URL path to scope (repeatable)")
	fs.Var(&rf.skipPaths, "skip-path", "URL path to skip (repeatable)")
	fs.Int64Var(&rf.tokenBudget, "token-budget", 0, "LLM token cap")
	fs.StringVar(&rf.maxDuration, "max-duration", "", "assessment wall clock (e.g. 30m, 4h)")
	fs.IntVar(&rf.maxChainDepth, "max-chain-depth", 0, "escalation chain depth limit")
	fs.IntVar(&rf.maxConcurrent, "max-concurrent", 0, "max concurrent cages")
	fs.IntVar(&rf.maxIterations, "max-iterations", 0, "max coordinator iterations (default 20)")
	fs.StringVar(&rf.context, "context", "", "free-text context for the LLM coordinator")
	fs.Var(&rf.focus, "focus", "vuln class to prioritize (repeatable)")
	fs.Var(&rf.skip, "skip", "path to deprioritize (repeatable)")
	fs.Var(&rf.endpoints, "endpoint", "endpoint to focus on (repeatable)")
	fs.Var(&rf.apiSpecs, "api-spec", "OpenAPI/GraphQL spec URL (repeatable)")
	fs.Var(&rf.knownWeaknesses, "known-weakness", "known weakness hint (repeatable)")
	fs.BoolVar(&rf.requirePoC, "require-poc", false, "require PoC for every finding")
	fs.BoolVar(&rf.headlessXSS, "headless-xss", false, "headless browser for XSS validation")
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
	skipPaths        stringSliceFlag
	tokenBudget      int64
	maxDuration      string
	maxChainDepth    int
	maxConcurrent    int
	maxIterations    int
	context          string
	focus            stringSliceFlag
	skip             stringSliceFlag
	endpoints        stringSliceFlag
	apiSpecs         stringSliceFlag
	knownWeaknesses  stringSliceFlag
	requirePoC       bool
	headlessXSS      bool
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
  agentcage run --agent ./my-agent.cage --target api.example.com --focus sqli --require-poc

Required (unless in plan file):
  --agent              .cage bundle (run 'agentcage pack <dir>' first)
  --target             target host(s), comma-separated

Plan file:
  --plan               path to assessment YAML plan file

Target scoping:
  --port               port to include (repeatable)
  --path               URL path to scope (repeatable)
  --skip-path          URL path to skip (repeatable)

Budget & limits:
  --token-budget       LLM token cap
  --max-duration       assessment wall clock (e.g. 30m, 4h)
  --max-chain-depth    escalation chain depth limit
  --max-concurrent     max concurrent cages

Guidance:
  --context            free-text context for the LLM coordinator
  --focus              vuln class to prioritize (repeatable)
  --skip               path to deprioritize (repeatable)
  --endpoint           endpoint to focus on (repeatable)
  --api-spec           OpenAPI/GraphQL spec URL (repeatable)
  --known-weakness     known weakness hint (repeatable)
  --require-poc        require PoC for every finding
  --headless-xss       headless browser for XSS validation

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
