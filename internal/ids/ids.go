package ids

import (
	"crypto/rand"
	"encoding/hex"
)

const suffixBytes = 5 // 10 hex chars

func generate(prefix string) string {
	b := make([]byte, suffixBytes)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand never fails on Linux/macOS in normal operation.
		// A failure here means the kernel RNG is broken; panic so we
		// don't silently issue predictable IDs.
		panic("ids: rand.Read failed: " + err.Error())
	}
	return prefix + hex.EncodeToString(b)
}

// Assessment returns a new assessment ID like "asmt_4f8b3e1c7a".
func Assessment() string { return generate("asmt_") }

// Cage returns a new cage ID like "cage_8a3f2e9b1c".
func Cage() string { return generate("cage_") }

// Finding returns a new finding ID like "fnd_b7d4e2a8c1".
func Finding() string { return generate("fnd_") }

// Intervention returns a new intervention ID like "ivn_3c5e7f9a2b".
func Intervention() string { return generate("ivn_") }

// VM returns a new VM ID like "vm_e1a8c9d2b5".
func VM() string { return generate("vm_") }

// RCA returns a new root-cause analysis ID like "rca_5d8c1f3a9b".
func RCA() string { return generate("rca_") }

// Audit returns a new audit entry ID like "aud_9f2e3a8b1d".
func Audit() string { return generate("aud_") }

// Hold returns a new payload-hold ID like "hold_3a1b9d8c5e".
func Hold() string { return generate("hold_") }
