// Package cagefile parses Cagefile manifests and packs agent
// directories into signed .cage bundles. The Cagefile is a small
// declarative format the operator writes (runtime, entrypoint,
// dependencies); Pack reads it, validates the entrypoint, hashes the
// agent files, and writes a gzipped tar to disk. Unpack reverses the
// process and verifies the manifest signature so a tampered bundle
// is rejected before any chroot install runs.
package cagefile
