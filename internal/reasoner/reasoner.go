// Package reasoner carries the reusable reasoning harness that
// `import --reasoning` writes into a generated reasoning agent, and renders that
// agent's Agentfile. The harness is Python and ships as source (embedded here),
// so the generated agent builds on a stock Python image and the operator can
// read and edit the brain right in their own directory.
package reasoner

import (
	_ "embed"
	"fmt"
	"strings"
)

//go:embed reasoner.py
var harness []byte

// HarnessFileName is where the harness is written in a generated reasoning agent
// and the ENTRYPOINT that runs it.
const HarnessFileName = "reasoner.py"

// HarnessSource is the reasoning-loop source written into a generated agent.
func HarnessSource() []byte { return harness }

// base is the image a reasoning agent builds on: a small Python with room for
// the MCP and OpenAI clients the harness installs.
const base = "python:3.12-slim"

// deferredModel is the MODEL a generated reasoning agent carries when the
// operator does not pin one with --model. Its provider is deliberately not one
// an operator configures, so the LLM gateway resolves it to the operator's
// default provider/model (DESIGN §9). Nothing ages: the operator upgrades their
// default once and every reasoning agent follows.
const deferredModel = "default/default"

// Params configure a generated reasoning agent.
type Params struct {
	// UsesRefs are the tool-collection references the agent reasons over, one
	// USES edge each. The harness aggregates every edge's tools into a single
	// menu, so one brain reasons across all of them.
	UsesRefs []string
	// Model is a provider/model to pin, or empty to defer to the operator's default.
	Model string
	// SystemPrompt is the reasoning prompt, or empty to use the harness default.
	SystemPrompt string
}

// Agentfile renders the reasoning agent that runs the harness over its USES
// tools. It is a brain over one or more tool collections: FROM a Python base,
// the harness deps, a MODEL that makes it a reasoning cage, a MAIN the runtime
// invokes, and one USES edge per imported collection.
func Agentfile(p Params) (string, error) {
	if len(p.UsesRefs) == 0 {
		return "", fmt.Errorf("reasoner: no tool-collection ref to USES")
	}
	model := p.Model
	if model == "" {
		model = deferredModel
	}

	lines := []string{
		"FROM " + base,
		"RUN pip install --no-cache-dir mcp openai",
		"MODEL " + model,
		"MAIN respond",
	}
	for _, ref := range p.UsesRefs {
		lines = append(lines, "USES "+ref)
	}
	if p.SystemPrompt != "" {
		// REASONER_SYSTEM_PROMPT, not an AGENTCAGE_ name: the parser reserves
		// that prefix for the runtime's own injected variables.
		lines = append(lines, "ENV REASONER_SYSTEM_PROMPT="+strings.ReplaceAll(p.SystemPrompt, "\n", " "))
	}
	lines = append(lines, "ENTRYPOINT python3 "+HarnessFileName)
	return strings.Join(lines, "\n") + "\n", nil
}
