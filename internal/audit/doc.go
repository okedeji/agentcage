// Package audit appends, signs, and verifies the tamper-evident
// HMAC-chained audit log for every cage. Each entry's signature
// covers the previous entry's hash, so modifying or removing any
// entry invalidates the chain from that point forward.
//
// Customers receive signed digests of the chain head and can verify
// tampering offline against any later digest, without needing access
// to the orchestrator or its signing keys. Key versioning is built in
// so old entries stay verifiable across rotations.
package audit
