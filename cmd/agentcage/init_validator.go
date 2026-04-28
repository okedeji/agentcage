package main

import (
	"context"
	"fmt"

	"github.com/okedeji/agentcage/internal/alert"
	"github.com/okedeji/agentcage/internal/cage"
	"github.com/okedeji/agentcage/internal/config"
	"github.com/okedeji/agentcage/internal/enforcement"
	"github.com/okedeji/agentcage/internal/ui"
	"github.com/okedeji/agentcage/internal/intervention"
)

// Compiled once at startup so per-request eval stays fast.
func buildPolicyEngine(cfg *config.Config) (*enforcement.OPAEngine, error) {
	ui.Step("Configuring policy engine")
	modules := enforcement.GenerateRegoModules(cfg)
	engine, err := enforcement.NewOPAEngineFromModules(modules)
	if err != nil {
		return nil, fmt.Errorf("creating OPA engine: %w", err)
	}
	return engine, nil
}

// Three validation layers: Go-side scope bounds, OPA scope policy,
// OPA cage-config policy. Every rejection fires a critical alert.
// OPA errors and OPA denials use different alert categories because
// they're different operational signals.
func buildCageValidator(
	cfg *config.Config,
	opaEngine *enforcement.OPAEngine,
	scopeValidator *enforcement.ScopeValidator,
	alertDispatcher *alert.Dispatcher,
) cage.ConfigValidator {
	return func(c cage.Config) error {
		if err := scopeValidator.ValidateCageConfig(context.Background(), c); err != nil {
			alertDispatcher.Dispatch(context.Background(), alert.Event{
				Source:       alert.SourcePolicy,
				Category:     alert.CategoryCageConfigViolation,
				Priority:     intervention.PriorityCritical,
				AssessmentID: c.AssessmentID,
				Description:  err.Error(),
				Details:      map[string]any{"layer": "go"},
			})
			return err
		}
		scopeDecision, scopeErr := opaEngine.EvaluateScope(context.Background(), c.Scope, cfg.Scope.Deny)
		if scopeErr != nil {
			alertDispatcher.Dispatch(context.Background(), alert.Event{
				Source:       alert.SourcePolicy,
				Category:     alert.CategoryScopeViolation,
				Priority:     intervention.PriorityCritical,
				AssessmentID: c.AssessmentID,
				Description:  fmt.Sprintf("OPA scope engine error: %v", scopeErr),
				Details:      map[string]any{"layer": "opa", "error": scopeErr.Error()},
			})
			return fmt.Errorf("evaluating scope policy: %w", scopeErr)
		}
		if !scopeDecision.Allowed {
			alertDispatcher.Dispatch(context.Background(), alert.Event{
				Source:       alert.SourcePolicy,
				Category:     alert.CategoryScopeViolation,
				Priority:     intervention.PriorityCritical,
				AssessmentID: c.AssessmentID,
				Description:  scopeDecision.Reason,
				Details:      map[string]any{"violations": scopeDecision.Violations, "layer": "opa"},
			})
			return fmt.Errorf("scope rejected: %s", scopeDecision.Reason)
		}
		decision, evalErr := opaEngine.EvaluateCageConfig(context.Background(), c)
		if evalErr != nil {
			alertDispatcher.Dispatch(context.Background(), alert.Event{
				Source:       alert.SourcePolicy,
				Category:     alert.CategoryCageConfigViolation,
				Priority:     intervention.PriorityCritical,
				AssessmentID: c.AssessmentID,
				Description:  fmt.Sprintf("OPA config engine error: %v", evalErr),
				Details:      map[string]any{"layer": "opa", "error": evalErr.Error()},
			})
			return fmt.Errorf("evaluating cage config policy: %w", evalErr)
		}
		if !decision.Allowed {
			alertDispatcher.Dispatch(context.Background(), alert.Event{
				Source:       alert.SourcePolicy,
				Category:     alert.CategoryCageConfigViolation,
				Priority:     intervention.PriorityCritical,
				AssessmentID: c.AssessmentID,
				Description:  decision.Reason,
				Details:      map[string]any{"violations": decision.Violations, "layer": "opa"},
			})
			return fmt.Errorf("cage config rejected: %s", decision.Reason)
		}
		return nil
	}
}
