// Package assessment owns the multi-phase workflow that turns a
// scope into validated findings. AssessmentWorkflow walks four
// phases: discovery, an LLM-driven exploitation loop, independent
// validation, and the human-review gate. Each phase spawns cages,
// collects findings, and signals the next phase.
//
// The Coordinator state is the snapshot the LLM planner sees on
// each iteration of the exploitation loop.
package assessment
