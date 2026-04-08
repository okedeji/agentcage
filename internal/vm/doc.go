// Package vm boots the lightweight Linux VM that hosts the
// orchestrator on macOS, where Firecracker doesn't run natively. The
// VM uses Apple Virtualization.framework via the Code-Hex/vz binding
// and shares the host's agentcage home directory through VirtioFS so
// the in-VM orchestrator and the host CLI both see the same data.
//
// Linux builds compile the stub instead. The package is the only
// place that touches platform-specific virtualization APIs; everything
// else in agentcage runs the same on darwin and linux.
package vm
