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
