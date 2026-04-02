package enforcement

import (
	"context"
	"fmt"

	"github.com/okedeji/agentcage/internal/cage"
)

var ErrUnknownCageType = fmt.Errorf("unknown cage type")

// AlertHandler evaluates a Falco alert and returns the tripwire policy that
// should govern the cage's response.
type AlertHandler interface {
	HandleAlert(ctx context.Context, cageType cage.Type, alert FalcoAlert) (TripwirePolicy, error)
}

type TripwireRuleSet struct {
	Rules   map[string]TripwirePolicy
	Default TripwirePolicy
}

type FalcoHandler struct {
	rulesets map[cage.Type]TripwireRuleSet
}

func NewFalcoHandler(rulesets map[cage.Type]TripwireRuleSet) *FalcoHandler {
	return &FalcoHandler{rulesets: rulesets}
}

func (h *FalcoHandler) HandleAlert(_ context.Context, cageType cage.Type, alert FalcoAlert) (TripwirePolicy, error) {
	rs, ok := h.rulesets[cageType]
	if !ok {
		return 0, fmt.Errorf("handling alert for cage type %s: %w", cageType, ErrUnknownCageType)
	}

	if policy, ok := rs.Rules[alert.RuleName]; ok {
		return policy, nil
	}

	return rs.Default, nil
}

// NewFalcoHandlerFromGenerated converts the output of GenerateFalcoRules into
// a FalcoHandler. Bridges the string-keyed generated tripwires to the
// cage.Type-keyed rulesets that FalcoHandler expects.
func NewFalcoHandlerFromGenerated(generated map[string]GeneratedTripwire) *FalcoHandler {
	rulesets := make(map[cage.Type]TripwireRuleSet, len(generated))
	for cageTypeStr, gt := range generated {
		rulesets[cage.TypeFromString(cageTypeStr)] = TripwireRuleSet{
			Rules:   gt.Rules,
			Default: gt.DefaultAction,
		}
	}
	return &FalcoHandler{rulesets: rulesets}
}

// FalcoAlertAdapter wraps a FalcoHandler to satisfy the cage.AlertHandler interface.
type FalcoAlertAdapter struct {
	handler *FalcoHandler
}

func NewFalcoAlertAdapter(handler *FalcoHandler) *FalcoAlertAdapter {
	return &FalcoAlertAdapter{handler: handler}
}

func (a *FalcoAlertAdapter) HandleAlert(ctx context.Context, cageType cage.Type, alert cage.AlertEvent) (cage.TripwirePolicy, error) {
	falcoAlert := FalcoAlert{
		RuleName: alert.RuleName,
		Priority: alert.Priority,
		Output:   alert.Output,
		CageID:   alert.CageID,
	}
	policy, err := a.handler.HandleAlert(ctx, cageType, falcoAlert)
	if err != nil {
		return 0, err
	}
	// Map enforcement TripwirePolicy to cage TripwirePolicy (values are identical by design)
	return cage.TripwirePolicy(policy), nil
}

// TripwirePolicyFromString converts a string from configuration into a TripwirePolicy value.
func TripwirePolicyFromString(s string) (TripwirePolicy, error) {
	switch s {
	case "log_and_continue":
		return TripwireLogAndContinue, nil
	case "human_review":
		return TripwireHumanReview, nil
	case "immediate_teardown":
		return TripwireImmediateTeardown, nil
	default:
		return 0, fmt.Errorf("unknown tripwire policy %q", s)
	}
}
