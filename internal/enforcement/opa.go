package enforcement

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/open-policy-agent/opa/v1/rego"

	"github.com/okedeji/agentcage/internal/cage"
)

type PolicyEngine interface {
	EvaluateScope(ctx context.Context, scope cage.Scope) (PolicyDecision, error)
	EvaluateCageConfig(ctx context.Context, config cage.Config) (PolicyDecision, error)
	EvaluatePayload(ctx context.Context, vulnClass string, payload string) (PayloadDecision, error)
	EvaluateCompliance(ctx context.Context, framework string, input map[string]any) (PolicyDecision, error)
}

type OPAEngine struct {
	scopeQuery        rego.PreparedEvalQuery
	cageTypeQuery     rego.PreparedEvalQuery
	payloadQueries    map[string]rego.PreparedEvalQuery
	complianceQueries map[string]rego.PreparedEvalQuery
}

func NewOPAEngine(policyDir string) (*OPAEngine, error) {
	modules, err := loadRegoFiles(policyDir)
	if err != nil {
		return nil, fmt.Errorf("loading rego files from %s: %w", policyDir, err)
	}

	e := &OPAEngine{
		payloadQueries:    make(map[string]rego.PreparedEvalQuery),
		complianceQueries: make(map[string]rego.PreparedEvalQuery),
	}

	scopeQuery, err := prepareQuery("data.agentcage.scope.deny", modules)
	if err != nil {
		return nil, fmt.Errorf("compiling scope policy: %w", err)
	}
	e.scopeQuery = scopeQuery

	cageTypeQuery, err := prepareQuery("data.agentcage.cage_types.deny", modules)
	if err != nil {
		return nil, fmt.Errorf("compiling cage_types policy: %w", err)
	}
	e.cageTypeQuery = cageTypeQuery

	for name, content := range modules {
		if parts := extractPolicyKey(name, "payload"); parts != "" {
			query, err := prepareQuery(fmt.Sprintf("data.agentcage.payload.%s.deny", parts), modules)
			if err != nil {
				return nil, fmt.Errorf("compiling payload policy %s: %w", parts, err)
			}
			e.payloadQueries[parts] = query
		}
		if parts := extractPolicyKey(name, "compliance"); parts != "" {
			query, err := prepareQuery(fmt.Sprintf("data.agentcage.compliance.%s.deny", parts), modules)
			if err != nil {
				return nil, fmt.Errorf("compiling compliance policy %s: %w", parts, err)
			}
			e.complianceQueries[parts] = query
		}
		_ = content
	}

	return e, nil
}

func (e *OPAEngine) EvaluateScope(ctx context.Context, scope cage.Scope) (PolicyDecision, error) {
	input := map[string]any{
		"hosts": scope.Hosts,
		"ports": scope.Ports,
		"paths": scope.Paths,
	}

	violations, err := evaluate(ctx, e.scopeQuery, input)
	if err != nil {
		return PolicyDecision{}, fmt.Errorf("evaluating scope policy: %w", err)
	}

	return policyDecisionFromViolations(violations), nil
}

func (e *OPAEngine) EvaluateCageConfig(ctx context.Context, config cage.Config) (PolicyDecision, error) {
	var llmConfig any
	if config.LLM != nil {
		llmConfig = map[string]any{
			"token_budget":     config.LLM.TokenBudget,
			"routing_strategy": config.LLM.RoutingStrategy,
		}
	}

	input := map[string]any{
		"cage_type":          config.Type.String(),
		"time_limit_seconds": int(config.TimeLimits.MaxDuration.Seconds()),
		"resources": map[string]any{
			"vcpus":     config.Resources.VCPUs,
			"memory_mb": config.Resources.MemoryMB,
		},
		"llm_config":        llmConfig,
		"parent_finding_id": config.ParentFindingID,
		"rate_limit_rps":    config.RateLimits.RequestsPerSecond,
	}

	violations, err := evaluate(ctx, e.cageTypeQuery, input)
	if err != nil {
		return PolicyDecision{}, fmt.Errorf("evaluating cage config policy: %w", err)
	}

	return policyDecisionFromViolations(violations), nil
}

func (e *OPAEngine) EvaluatePayload(ctx context.Context, vulnClass string, payload string) (PayloadDecision, error) {
	q, ok := e.payloadQueries[vulnClass]
	if !ok {
		return PayloadAllow, nil
	}

	input := map[string]any{
		"payload": payload,
	}

	violations, err := evaluate(ctx, q, input)
	if err != nil {
		return PayloadBlock, fmt.Errorf("evaluating payload policy for %s: %w", vulnClass, err)
	}

	if len(violations) > 0 {
		return PayloadBlock, nil
	}
	return PayloadAllow, nil
}

func (e *OPAEngine) EvaluateCompliance(ctx context.Context, framework string, input map[string]any) (PolicyDecision, error) {
	q, ok := e.complianceQueries[framework]
	if !ok {
		return PolicyDecision{}, fmt.Errorf("no compliance policy for framework %q", framework)
	}

	violations, err := evaluate(ctx, q, input)
	if err != nil {
		return PolicyDecision{}, fmt.Errorf("evaluating compliance policy for %s: %w", framework, err)
	}

	return policyDecisionFromViolations(violations), nil
}

func loadRegoFiles(dir string) (map[string]string, error) {
	modules := make(map[string]string)

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || !strings.HasSuffix(path, ".rego") {
			return nil
		}

		content, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("reading %s: %w", path, err)
		}

		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return fmt.Errorf("computing relative path for %s: %w", path, err)
		}

		modules[rel] = string(content)
		return nil
	})
	if err != nil {
		return nil, err
	}

	return modules, nil
}

func prepareQuery(query string, modules map[string]string) (rego.PreparedEvalQuery, error) {
	opts := []func(*rego.Rego){
		rego.Query(query),
	}
	for name, content := range modules {
		opts = append(opts, rego.Module(name, content))
	}

	r := rego.New(opts...)
	return r.PrepareForEval(context.Background())
}

func evaluate(ctx context.Context, query rego.PreparedEvalQuery, input map[string]any) ([]string, error) {
	rs, err := query.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		return nil, err
	}
	return extractDenials(rs), nil
}

func extractDenials(rs rego.ResultSet) []string {
	var denials []string
	for _, result := range rs {
		for _, expr := range result.Expressions {
			set, ok := expr.Value.([]any)
			if !ok {
				continue
			}
			for _, item := range set {
				if s, ok := item.(string); ok {
					denials = append(denials, s)
				}
			}
		}
	}
	return denials
}

func policyDecisionFromViolations(violations []string) PolicyDecision {
	if len(violations) == 0 {
		return PolicyDecision{Allowed: true}
	}
	return PolicyDecision{
		Allowed:    false,
		Reason:     violations[0],
		Violations: violations,
	}
}

// extractPolicyKey returns the OPA package leaf name for a rego file under a
// given subdirectory (e.g. "payload" or "compliance"). Returns empty string if
// the file does not live under that subdirectory.
func extractPolicyKey(filename, subdir string) string {
	parts := strings.Split(filepath.ToSlash(filename), "/")
	if len(parts) < 2 || parts[0] != subdir {
		return ""
	}
	base := strings.TrimSuffix(parts[1], ".rego")
	base = strings.TrimSuffix(base, "_safe")
	return base
}
