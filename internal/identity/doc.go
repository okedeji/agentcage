// Package identity issues SPIFFE workload identities for cages and
// authenticates each cage to Vault to fetch its scoped secrets. Two
// auth paths: production uses a real JWT-SVID from SPIRE bound to the
// cage's SPIFFE ID, and dev uses a shared static token from `vault
// server -dev`.
//
// This is the only package in the codebase where credential material
// lives in memory. Every type that holds a token, key, or SVID raw
// bytes implements String, GoString, and MarshalJSON to redact the
// secret field. Adding a new credential-bearing type without those
// methods is a leak waiting to happen.
package identity
