// Command cage-init is PID 1 inside the cage microVM. It reads the
// cage config injected at /etc/agentcage/cage.json, starts the
// findings-sidecar and payload-proxy, then execs the agent
// entrypoint as a child process. cage-init stays running as PID 1 so
// it can reap zombies and supervise the in-cage processes.
package main
