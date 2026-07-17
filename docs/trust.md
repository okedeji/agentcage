# trust

Manage the publisher signing keys this host has pinned. mcpvessel trusts a publisher's key on first use: the first time you pull a signed bundle from a namespace, the key that signed it is pinned, and every later pull from that namespace must be signed by the same key. A different key fails the pull closed. `trust ls` shows what is pinned; `trust rm` unpins a namespace so the next signed pull re-pins.

```
mcpvessel trust ls
mcpvessel trust rm SCOPE
```

`trust` is a read-and-remove interface over a small state file. It never pins a key itself; pinning happens as a side effect of a signed pull. The command exists to inspect that state and to undo a pin once a publisher's new key is verified out of band.

## Trust on first use

A pushed bundle can carry a signature: an ed25519 signature over the bundle's manifest digest plus the full repository it was pushed to (`ghcr.io/okedeji/tool`). The signature proves the bytes were not altered and that they were signed for this exact name, but it does not by itself say the key is the publisher's. That is what pinning decides.

Pinning is keyed on a **scope**, not the full repository. A scope is the registry host plus the first path segment of the repository, the namespace a single publisher controls: `ghcr.io/okedeji/tool` and `ghcr.io/okedeji/other` share the scope `ghcr.io/okedeji`. The first verified signed pull from a scope records that signer's public key as the scope's pin. Every later pull from any repository in that scope is held to the same key.

Enforcement runs at one point: cache ingest, inside `Pull`. Every command that fetches a bundle over the network (`pull`, and `run`, `serve`, `call`, `inspect` when they resolve a reference they do not already have) passes through it, so the policy holds everywhere, not just on an explicit `pull`. A digest-pinned reference already in the local cache returns without any network access and is not re-verified.

Three outcomes at ingest, all reported on stderr so they do not pollute a command's real output:

- **First pull from a scope, signature valid**: the key is pinned. `Signature verified; pinned signing key <fp> for <scope> (first use)`.
- **Later pull, same key**: passes silently past the check. `Signature verified (key <fp>)`.
- **Later pull, different key**: fails closed. Nothing is cached, the command errors:

  ```
  SIGNING KEY MISMATCH for ghcr.io/okedeji: bundle is signed by key <new> but key <old> was pinned 2026-02-10.
  The publisher may have rotated keys, or this artifact is not from them.
  If you have verified the new key out of band, run 'mcpvessel trust rm ghcr.io/okedeji' and pull again
  ```

An unsigned bundle (no signature published next to it) is not a mismatch. It pins nothing and passes, unless strict mode is on (see [Strict mode](#strict-mode)). A registry that cannot answer whether a signature exists is treated as an error, not as an unsigned bundle, so a broken registry never silently downgrades to no verification.

## trust ls

Lists every pinned scope, one row each, sorted by scope.

```
mcpvessel trust ls
```

Takes no arguments and no flags. Columns:

- **SCOPE**: the namespace, `registry-host/owner`.
- **KEY**: the pinned key's fingerprint, the first 12 hex chars of the sha256 of its public key. This is the value to compare against a fingerprint a publisher advertises.
- **PINNED**: the date the key was first pinned (`YYYY-MM-DD`).

With nothing pinned it prints a single line and exits zero: `No pinned keys. A key is pinned on the first pull of a signed bundle.`

## trust rm

Removes the pin for one scope.

```
mcpvessel trust rm SCOPE
```

Takes exactly one argument, the scope to unpin (`ghcr.io/okedeji`, the same string `trust ls` shows in its SCOPE column). It deletes that scope's pin and writes the store back. After that, the next signed pull from the scope re-pins whatever key it sees, treating it as a first use again.

If no pin exists for the given scope, nothing is changed and the command errors: `no pinned key for <scope>; 'mcpvessel trust ls' shows what is pinned`. The scope must match exactly; a repository path or a mismatched host will not resolve to a pin.

Unpin only after you have confirmed the publisher's new key through some channel other than the pull itself (their README, their MCP Registry entry, a message from them). Removing the pin is the deliberate act of accepting a new key; do it blindly and a mismatch that was protecting you becomes a silent acceptance of an unknown key.

## Strict mode

By default an unsigned bundle pulls fine, since much of the ecosystem is still unsigned. Set **`VESSEL_REQUIRE_SIGNATURES`** to a truthy value and every pull must carry a valid signature: an unsigned bundle fails closed with `<ref> is not signed and VESSEL_REQUIRE_SIGNATURES is set; unset it or ask the publisher for a signed push`.

Truthy means any value except empty, `0`, or `false` (case-insensitive, surrounding whitespace ignored). `VESSEL_REQUIRE_SIGNATURES=1` and `VESSEL_REQUIRE_SIGNATURES=true` both turn it on; `VESSEL_REQUIRE_SIGNATURES=0`, `=false`, or leaving it unset leave it off.

Strict mode changes the unsigned case only. It does not loosen the mismatch check (a wrong key always fails) and it does not pin anything on its own; pinning still happens through a valid signed pull.

## Where the state lives

Pins are stored in `~/.mcpvessel/trust.json`, a JSON object mapping each scope to its pinned public key and pin date, written `0600`. `VESSEL_HOME`, when set, relocates the `~/.mcpvessel` root, so the trust store moves with it. A missing file is an empty store. A file that exists but does not parse fails closed rather than silently dropping every pin, so a corrupt store surfaces as an error instead of quietly re-trusting everything.

The trust store is separate from this host's own signing key (`~/.mcpvessel/signing-key.json`, managed by [keys](keys.md)). One holds the keys you trust in others; the other holds the key you sign as.

## Arguments and flags

| Subcommand | Args | Flags |
| --- | --- | --- |
| `trust ls` | none | none |
| `trust rm` | exactly one `SCOPE` | none |

Neither subcommand takes any flag.

## Examples

```sh
# See which publisher keys this host has pinned.
mcpvessel trust ls

# Output:
# SCOPE               KEY           PINNED
# ghcr.io/okedeji     4f3a9c1e8b02  2026-02-10

# A publisher rotated keys and you verified the new fingerprint out of band.
# Drop the old pin, then pull to re-pin the new key.
mcpvessel trust rm ghcr.io/okedeji
mcpvessel pull ghcr.io/okedeji/tool:1.4.0

# Require every pull to be signed for one command.
VESSEL_REQUIRE_SIGNATURES=1 mcpvessel run ghcr.io/okedeji/tool:1.4.0
```

## Notes

- `trust` never contacts a registry. It only reads and edits the local store. Pinning is done by a pull, not by this command.
- A pin is per namespace, not per bundle. Removing `ghcr.io/okedeji` unpins every repository under that owner at once; the next signed pull from any of them re-pins.
- A digest-pinned reference already cached is served from disk with no verification, since its content is fixed by the digest. Verification is a network-ingest boundary, not a run-time one.
- The fingerprint in `trust ls` and in a mismatch error is the same 12-char value a publisher advertises for their key, so comparing them is a direct string match. It is derived from the public key alone and is safe to publish.
- A mismatch caches nothing and fails the whole command. There is no override flag; the only way past is to verify the new key and `trust rm` the scope.
- Strict mode is read from the environment on every pull, so it can be scoped to a single command by prefixing that command, as in the example, rather than exported globally.

## See also

- [keys](keys.md): this host's own signing key, the one push signs with. `trust` pins other publishers' keys; `keys` manages yours.
- [push](push.md): signs a bundle after pushing it, generating this host's key on first use, and prints the fingerprint to advertise.
- [pull](pull.md): where a signed pull pins a key and where a mismatch or strict-mode failure surfaces.
- [run](run.md), [serve](serve.md), [call](call.md): resolve references through the same pull path, so the same pinning and enforcement apply.
- [Ship it](../README.md#ship-it): pushing a bundle, and that it is signed on push and verified on pull.
- [SECURITY.md](../SECURITY.md#signing-and-trust): the signing and trust model in full, and how to verify a pull.
