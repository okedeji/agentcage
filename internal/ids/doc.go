// Package ids generates typed short identifiers for every entity in
// the system: assessments, cages, findings, interventions, VMs, audit
// entries, RCA documents, and payload holds.
//
// Each ID has a type prefix so it is self-describing in logs, tables,
// CLI output, and gRPC error messages. An operator who sees
// "cage_4f8b3e1c7a" in a stack trace knows immediately what it is and
// can paste it into "agentcage logs cage <id>" without guessing.
//
// The random suffix is 10 hex chars (40 bits of entropy from
// crypto/rand). Collision probability is ~1 in a billion per billion
// items per type, well beyond anything this system will produce. The
// goal was usability, not cryptographic uniqueness; UUIDs would have
// been 36 chars of cargo cult.
package ids
