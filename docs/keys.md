# keys

Show, back up, and move this host's bundle signing key. `keys` prints the public half of the ed25519 key push signs with, generating the keypair on first use. `keys export` and `keys import` move that one identity between machines so a laptop and CI sign as the same publisher. This page is about your own signing key. Pinning other publishers' keys is a separate command, [trust](trust.md).

```
mcpvessel keys              # show the public key, generating one if needed
mcpvessel keys export       # write the private key to stdout, for backup or CI
mcpvessel keys import       # install a key read from stdin
```

Push signs each bundle it uploads: a signature is ed25519 over the bundle's manifest digest plus the repository it went to, so a valid signature cannot be replayed onto other bytes or another publisher's name. Pull verifies that signature and pins your key on first use. `keys` is how you see the key, publish its fingerprint so pullers can pin the right one, and carry the same key to a second machine.

## The signing key

One keypair per host, held in `~/.mcpvessel/signing-key.json` (or under `$VESSEL_HOME` when that is set). The file is a small JSON document: the algorithm (`ed25519`), the 32-byte seed and matching public key (both base64), and a creation timestamp. The seed alone reconstructs the keypair, so the whole private identity lives in that one file. It is written `0600` in a `0700` directory and never leaves the host on its own; only `keys export` sends it anywhere, and only where you redirect it.

The key is generated lazily. The first `mcpvessel keys`, or the first signed `push`, calls `EnsureKey`: if the file exists it is loaded, otherwise a fresh ed25519 keypair is generated and persisted. Loading fails closed. A file whose algorithm is not `ed25519`, whose seed is not 32 bytes, or whose stored public key does not match the seed is rejected rather than used, so a truncated or tampered key file is an error, not a silent wrong signature.

The **fingerprint** is the short, publishable name for a key: the first 12 hex characters of the sha256 of its base64 public key. It is stable across encodings and safe to put in a README or an MCP Registry entry. A first pull pins your key by this identity, so publishing the fingerprint is how a puller confirms they pinned the key you meant.

## keys

`mcpvessel keys` takes no arguments. It ensures a key exists, then prints three lines to stdout:

```
Fingerprint: 3f2a1c9d0b74
Public key:  MCowBQYDK2VwAyEA...
Path:        /Users/you/.mcpvessel/signing-key.json
```

If this call generated the key, it also writes `Generated a new signing key` to stderr, so the fingerprint and key on stdout stay clean if you are capturing them. Only the public half is shown. The private seed never prints here; use `keys export` for that.

## keys export

`mcpvessel keys export` writes the raw signing-key file (the full private key, seed included) to stdout, for a backup or to move the identity to another machine. It takes no arguments.

It refuses to print to a terminal. If stdout is an interactive TTY it errors without writing a byte, so a private key never lands in scrollback:

```
refusing to print a private key to a terminal; redirect it: mcpvessel keys export > mcpvessel-signing.key
```

Redirect it to a file or a pipe and it proceeds. The key is validated before it is written, so a corrupt key file is caught here, at export, rather than on the other machine at import. If no key exists yet, export does not generate one; it errors and points you at how a key is made:

```
no signing key to export; 'mcpvessel keys' or a signed push generates one
```

The bytes it writes are exactly the on-disk key file, so `keys export` on one host and `keys import` on another round-trips the same identity.

## keys import

`mcpvessel keys import` installs a key produced by `keys export` so this machine signs as the same publisher. It takes no arguments and reads the key from stdin, never from a command-line argument, so the key stays out of shell history and the process table.

It validates the incoming key the same way loading does (algorithm, seed length, public key matching the seed), then decides what to write:

- **No key here yet:** the imported key is written to `~/.mcpvessel/signing-key.json` at `0600`.
- **The same key is already here:** a no-op. Import reports success and leaves the file untouched.
- **A different key is already here:** refused, to protect what this host already signs as. The error names both fingerprints and tells you to pass `--force`:

  ```
  a different signing key already exists here (3f2a1c9d0b74); pass --force to replace it with a1b2c3d4e5f6
  ```

`--force` replaces the existing key with the imported one. On success import prints the fingerprint it installed:

```
Imported signing key a1b2c3d4e5f6
```

## Flags

| Command | Flag | Meaning |
| --- | --- | --- |
| `keys import` | `--force` | Replace an existing different key. Without it, importing a key that differs from the one already installed is refused. Importing the identical key is a no-op either way. |

`keys` and `keys export` take no flags and no arguments.

## Examples

```sh
# Show this host's signing key and its fingerprint (generating one on first run).
mcpvessel keys

# Back the key up to a file (a terminal is refused; a redirect is required).
mcpvessel keys export > mcpvessel-signing.key

# Move the identity to CI so a build there signs as you.
mcpvessel keys export | ssh ci 'mcpvessel keys import'

# Restore or install a key from a backup file.
mcpvessel keys import < mcpvessel-signing.key
```

## Notes

- `export` writes the private key. Treat its output like any secret: a redirect to a file, an SSH pipe, or a secret store, never a shared terminal. The TTY refusal is a guardrail, not the whole of it.
- A signed `push` generates the key silently on first use, then prints the fingerprint and path and tells you to back it up. You do not have to run `keys` first; it is there to show the key and its fingerprint on demand.
- Lose the key and you cannot sign as the same publisher again. A puller who pinned the old fingerprint will reject a bundle signed by a new key until they clear the pin (see [trust](trust.md)). Back the key up with `keys export`, or move it to every machine that publishes for you.
- The fingerprint is the same on every machine that holds the same key, because it is derived from the public key alone. That is what lets a laptop and CI push under one identity after `export` / `import`.
- Everything here honors `$VESSEL_HOME`. Point it at a different directory and the key file, generation, and lookup all follow it, which is handy for isolating a CI identity from your personal one on the same box.

## See also

- [push](push.md): signs each bundle with this key; `--no-sign` pushes without a signature.
- [pull](pull.md): verifies the signature and pins the publisher's key on first use.
- [trust](trust.md): list and remove the *other* publishers' keys this host has pinned.
- [Ship it](../README.md#ship-it): pushing, signing, and pulling a bundle end to end.
