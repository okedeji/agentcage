package assessment

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/okedeji/agentcage/internal/gateway"
)

// Planner calls the LLM to decide what cages to spawn next.
type Planner struct {
	client *gateway.Client
}

func NewPlanner(client *gateway.Client) *Planner {
	return &Planner{client: client}
}

const coordinatorSystemPrompt = `You are the coordinator for an autonomous penetration testing assessment.

Your role is to analyze what has been tested so far, what findings have been discovered, and decide what to test next. You orchestrate thousands of short-lived agents ("cages"), each with a narrow objective.

You will receive a JSON state object containing:
- scope: the target hosts, ports, and paths
- findings: vulnerabilities discovered so far
- coverage: which endpoints have been tested for which vulnerability classes
- budget: tokens used vs total, time elapsed vs limit
- cages_completed: what cages have already run and their outcomes

You must respond with a JSON object:
{
  "done": false,
  "reason": "explanation of your strategy",
  "actions": [
    {
      "type": "discovery|validator|escalation",
      "scope": {"hosts": ["..."], "ports": ["..."], "paths": ["..."]},
      "vuln_class": "sqli|xss|rce|ssrf|idor|auth|...",
      "finding_id": "only for validator/escalation",
      "objective": "natural language description of what this cage should do",
      "priority": 1
    }
  ]
}

Rules:
- Set "done": true when you believe the target has been sufficiently tested or budget is low
- Discovery cages explore attack surface and find candidate vulnerabilities
- Validator cages confirm a specific finding is real (requires finding_id)
- Escalation cages attempt to chain from a validated finding (requires finding_id)
- Prioritize uncovered endpoints and high-value targets (admin panels, auth, API endpoints)
- Do not re-test combinations already in the coverage map
- Be concise in objectives — the agent LLM inside the cage will interpret them
- Respect budget: if tokens_used > 80% of token_budget, wrap up with validators only
- Maximum 10 actions per response`

// PlanNextActions sends the coordinator state to the LLM and returns
// structured decisions about what cages to spawn.
func (p *Planner) PlanNextActions(ctx context.Context, state CoordinatorState) (CoordinatorDecision, error) {
	stateJSON, err := json.Marshal(state)
	if err != nil {
		return CoordinatorDecision{}, fmt.Errorf("marshaling coordinator state: %w", err)
	}

	resp, err := p.client.ChatCompletion(ctx, "coordinator-"+state.AssessmentID, state.AssessmentID, state.TokenBudget, gateway.LLMRequest{
		Messages: []gateway.LLMMessage{
			{Role: "system", Content: coordinatorSystemPrompt},
			{Role: "user", Content: string(stateJSON)},
		},
	})
	if err != nil {
		return CoordinatorDecision{}, fmt.Errorf("calling LLM for coordinator decision: %w", err)
	}

	if len(resp.Choices) == 0 {
		return CoordinatorDecision{}, fmt.Errorf("LLM returned no choices")
	}

	content := resp.Choices[0].Message.Content
	var decision CoordinatorDecision
	if err := json.Unmarshal([]byte(content), &decision); err != nil {
		return CoordinatorDecision{}, fmt.Errorf("parsing coordinator decision from LLM response: %w (response: %s)", err, truncate(content, 200))
	}

	if err := validateDecision(decision); err != nil {
		return CoordinatorDecision{}, fmt.Errorf("invalid coordinator decision: %w", err)
	}

	return decision, nil
}

func validateDecision(d CoordinatorDecision) error {
	if d.Done {
		return nil
	}

	if len(d.Actions) == 0 {
		return fmt.Errorf("decision is not done but has no actions")
	}

	if len(d.Actions) > 10 {
		return fmt.Errorf("too many actions: %d (max 10)", len(d.Actions))
	}

	for i, a := range d.Actions {
		switch a.Type {
		case "discovery", "validator", "escalation":
		default:
			return fmt.Errorf("action %d: invalid type %q", i, a.Type)
		}

		if len(a.Scope.Hosts) == 0 {
			return fmt.Errorf("action %d: scope must have at least one host", i)
		}

		if a.Objective == "" {
			return fmt.Errorf("action %d: objective is required", i)
		}

		if (a.Type == "validator" || a.Type == "escalation") && a.FindingID == "" {
			return fmt.Errorf("action %d: %s cages require a finding_id", i, a.Type)
		}
	}

	return nil
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
