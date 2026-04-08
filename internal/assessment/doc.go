// Package assessment owns the multi-phase workflow that turns a
// scope into validated findings. AssessmentWorkflow walks five
// phases: surface mapping, an LLM-driven exploitation loop, proof
// validation, escalation chaining, and the human-review gate. Each
// phase spawns cages, collects findings, and signals the next phase.
//
// The proof library lives here too. Validation walks every candidate
// finding by vuln class and looks up a proof; missing proofs trigger
// proof_gap interventions that block the workflow until the operator
// adds a proof and resolves the intervention. The Coordinator state
// is the snapshot the LLM planner sees on each iteration.
package assessment
