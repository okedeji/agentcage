# Bundle signing

Every bundle a registry hands you is a stranger's code. The cage bounds what it
can do at run time; signing tells you who published it before you run it at
all. agentcage signs every push and verifies every pull by default, pinning a
publisher's key on first use.

## What a signature proves

A signature is ed25519 over the bundle's OCI manifest digest plus the
repository it was pushed to. Verifying it proves three things:

1. The bytes are exactly what the key holder pushed (the digest covers the
   whole bundle, and the manifest locks every USES dependency by digest, so
   one verified root covers its whole tree).
2. The signature belongs to these bytes and this name. It cannot be replayed
   onto a different bundle or onto another publisher's repository.
3. The signer holds the same key as every previous signed pull from that
   publisher (see trust below).

What it does not prove: that the publisher is who they claim to be on GitHub,
or that the code is safe. Identity-bound signing (Sigstore keyless against the
publisher's GitHub identity) is on the roadmap; the cage is what bounds unsafe
code either way.

## Signing (publishers)

```sh
agentcage push @you/agent:0.1
```

Signing is the default; there is nothing to enable. The first signed push
generates an ed25519 keypair at `~/.agentcage/signing-key.json` (0600). The
private key never leaves your machine; the signature is pushed as a small OCI
artifact next to the bundle (tag `sha256-<digest>.sig`, the cosign
convention), so it works on any OCI registry with no extra infrastructure.
`--no-sign` pushes without a signature; pulls will say so.

`agentcage keys` prints your public key and its fingerprint. Publish the
fingerprint where pullers can see it (your README, your MCP Registry entry) so
their first pull pins the right key.

One publisher, one key: a laptop and CI signing with different keys would trip
your own consumers' pins. Move the key, never regenerate it:

```sh
agentcage keys export > agentcage-signing.key    # refuses a terminal
agentcage keys import < agentcage-signing.key    # on the other machine
```

Back the export up. A lost key means a new key, and everyone who pinned the
old one sees a mismatch until they `trust rm` you.

## Verifying (pullers)

Verification is automatic at cache ingest, the one point every network pull
passes (`pull`, `run`, `call`, USES resolution). The cache is digest-addressed
and immutable, so a bundle verified on the way in stays verified.

Trust is on first use, SSH known_hosts semantics:

- First pull of a signed bundle from a publisher: the key is pinned for that
  scope (registry host + owner, e.g. `ghcr.io/okedeji`) and you are told.
- Every later pull from that scope must be signed by the pinned key. A
  different key fails closed, with both fingerprints in the error.
- `agentcage trust ls` shows your pins; `agentcage trust rm SCOPE` clears one
  after you have verified a publisher's new key out of band.

Unsigned bundles pull with a notice. To refuse them outright:

```sh
agentcage config env set AGENTCAGE_REQUIRE_SIGNATURES 1
```

## Threat model, honestly

| Threat | Covered? |
|---|---|
| Registry account compromise republishes a tag | Yes: the new bytes are not signed by the pinned key, pull fails closed |
| Mirror or cache serves altered bytes | Yes: digest verification catches alteration; signature catches a re-signed swap |
| Signature replayed onto another repo or digest | Yes: both are inside the signed payload |
| Malicious sub-agent swapped into a tree | Yes, transitively: the parent's manifest locks digests, the root signature covers the manifest |
| First pull is already compromised | No: trust on first use trusts the first key it sees. Check the publisher's fingerprint out of band for high-stakes pulls |
| Publisher's laptop (private key) compromised | No: the attacker signs as them until the key is rotated and pins are cleared |
| Publisher pushes malicious code themselves | No: signing proves origin, not intent. That is what the cage is for |

## Roadmap

Sigstore keyless signing (cosign-compatible, key bound to the publisher's
GitHub identity via OIDC, transparency-logged) replaces raw keypairs once the
flow is worth its dependency weight. The artifact layout already follows the
cosign tag convention so the migration is additive.
