// Command agentcage is the orchestrator binary and CLI for the
// agentcage platform. It dispatches subcommands (init, run, assessments,
// findings, report, interventions, fleet, db, logs, proof, audit,
// falco). All gRPC commands dial the orchestrator directly.
//
// `agentcage init` is the long-running entry point: it boots every
// embedded service (Postgres, Temporal, NATS, SPIRE, Vault, Falco),
// wires the cage and assessment workflows to Temporal workers,
// starts the gRPC server, and sits waiting for cages to be created.
// runInit in cmd_init.go is the boot story; the init_*.go files
// hold each phase.
package main
