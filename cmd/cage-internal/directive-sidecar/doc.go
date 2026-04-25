// Command directive-sidecar runs inside the cage microVM and
// bridges orchestrator directives to the agent process. It listens
// on vsock for directives (scope updates, early termination) and
// writes them to a well-known path the agent reads. It also handles
// agent hold requests: the agent writes a hold request, the sidecar
// forwards it to the orchestrator over vsock, and blocks until the
// operator resolves or the intervention times out.
package main
