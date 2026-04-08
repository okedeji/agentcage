// Package cage owns the lifecycle of one isolated cage from creation
// through teardown. The cage is the trust boundary: everything inside
// the microVM is hostile by assumption, and this package is the
// orchestrator's side of that boundary.
//
// CageWorkflow is the 13-step Temporal workflow that brings a cage
// up, monitors it, and tears it down. The setup phase issues a
// SPIFFE identity, fetches scoped secrets from Vault, provisions a
// Firecracker microVM, applies network isolation, and starts the
// agent. The monitor phase runs until the cage completes, times out,
// or trips a Falco rule that signals immediate teardown. The teardown
// phase runs every cleanup step regardless of individual failures
// because an orphaned VM running exploit code with valid credentials
// is the worst outcome.
//
// The activity implementations wire each workflow step to its real
// dependency. RootfsBuilder assembles a per-cage ext4 image from a
// base image and a .cage bundle, with bundle integrity verified
// before any chroot install runs. FirecrackerProvisioner manages the
// per-cage Firecracker process, TAP device, and API socket.
// FalcoAlertReader streams behavioral alerts from the Falco unix
// socket into the monitor activity, reconnecting with backoff so a
// brief Falco blip doesn't silently degrade the tripwire layer.
package cage
