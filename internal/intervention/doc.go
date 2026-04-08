// Package intervention is the human-in-the-loop seam where the
// autonomous orchestrator hands control back to a person. When the
// system hits a decision it shouldn't make alone (a tripwire, a
// payload review, a missing proof, a report review, a policy
// violation), it enqueues an intervention. An operator resolves it
// via CLI, and the resolution signals the relevant Temporal workflow
// to resume, kill, or skip.
//
// The package owns the in-memory pending queue, the Postgres store
// for durability, the timeout enforcer that escalates abandoned
// interventions to a default action, and the notifier fan-out (log
// plus webhooks) that lets operators know they need to act.
package intervention
