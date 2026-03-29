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

// DefaultRuleSets returns the standard Falco-to-tripwire mappings for each cage type.
func DefaultRuleSets() map[cage.Type]TripwireRuleSet {
	return map[cage.Type]TripwireRuleSet{
		cage.TypeDiscovery: {
			Rules: map[string]TripwirePolicy{
				"Unexpected Privileged Shell in Discovery Cage":  TripwireHumanReview,
				"Sensitive File Write in Discovery Cage":         TripwireLogAndContinue,
				"Privilege Escalation Attempt in Discovery Cage": TripwireImmediateTeardown,
				"Excessive Process Forking in Discovery Cage":    TripwireLogAndContinue,
			},
			Default: TripwireLogAndContinue,
		},
		cage.TypeValidator: {
			Rules: map[string]TripwirePolicy{
				"Any Shell Spawn in Validator Cage":              TripwireImmediateTeardown,
				"Any File Write in Validator Cage":               TripwireHumanReview,
				"Unexpected Network Connection in Validator Cage": TripwireLogAndContinue,
				"Privilege Escalation in Validator Cage":         TripwireImmediateTeardown,
				"Unexpected Process in Validator Cage":           TripwireImmediateTeardown,
			},
			Default: TripwireHumanReview,
		},
		cage.TypeEscalation: {
			Rules: map[string]TripwirePolicy{
				"Privileged Shell in Escalation Cage":            TripwireHumanReview,
				"Sensitive File Write in Escalation Cage":        TripwireHumanReview,
				"Privilege Escalation in Escalation Cage":        TripwireImmediateTeardown,
				"Lateral Movement Attempt in Escalation Cage":    TripwireImmediateTeardown,
			},
			Default: TripwireHumanReview,
		},
	}
}
