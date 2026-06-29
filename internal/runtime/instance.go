package runtime

import (
	"crypto/sha256"
	"encoding/hex"
)

// InstanceRunID names one lifetime of a per-session served instance: the agent's
// address, a short hash of the client's MCP session id so the name says which
// client it serves, and a unique suffix per boot. The suffix is what keeps a
// session that goes idle, is reaped, and reconnects from reusing the prior
// instance's id and overwriting its finished history record. Concurrent instances
// of the same bundle never collide on a container name. Reuse of a still-live
// instance is the manager's map, not this id, so a fresh id per boot is correct.
func InstanceRunID(address, sessionID string) string {
	sum := sha256.Sum256([]byte(sessionID))
	session := hex.EncodeToString(sum[:])[:8]
	return sanitizeRef(address) + "-" + session + "-" + uniqueSuffix()
}
