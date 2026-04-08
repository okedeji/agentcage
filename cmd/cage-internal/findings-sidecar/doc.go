// Command findings-sidecar runs inside each cage and forwards
// findings emitted by the agent to the orchestrator's NATS bus. The
// agent writes JSON-encoded findings to a Unix socket; the sidecar
// validates each one and republishes it on the assessment's findings
// stream. Keeping the sidecar between the agent and NATS lets the
// orchestrator drop bad findings without round-tripping malformed
// data into the bus.
package main
