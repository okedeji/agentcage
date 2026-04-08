// Package embedded manages the lifecycle of every infrastructure
// service agentcage can run in-process: Postgres, Temporal, NATS,
// SPIRE, Vault, and Falco. Each service implements a small lifecycle
// interface (Download, Start, Stop, Health) and Manager runs them in
// dependency order.
//
// Services the operator configured as external (via infrastructure.*
// in config.yaml) are skipped at startup. The rest are downloaded
// (if missing), started as subprocesses with log capture and PID
// files, and torn down with bounded deadlines on shutdown. NATS is
// the exception: it runs in-process as a Go library because the
// JetStream Go server is small and removes the binary download.
package embedded
