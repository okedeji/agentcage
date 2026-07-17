# store

Inspect and populate the local bundle store, the content-addressed directory under `~/.mcpvessel/store` where `build` writes and where `run`, `call`, `serve`, and `push` read back by reference. It has three subcommands: `ls` lists what resolves locally, `load` adds a `.agent` file someone handed you, and `rm` clears bundles you no longer need. No daemon and no network are involved; every operation is a direct read or write of files on disk.

```
mcpvessel store ls [--json]
mcpvessel store load FILE [-t REF]
mcpvessel store rm REF|HASH...
```

## The store on disk

The store lives at `~/.mcpvessel/store`, or under `$VESSEL_HOME/store` when `VESSEL_HOME` is set (the same variable that relocates the rest of mcpvessel's state). The directory is created lazily by the first write, so a fresh install has none until you build or load something.

Inside are two directories:

- **`bundles/`** holds the bundle bytes, one `.agent` file per bundle, named by its manifest `files_hash`. The hash is content-addressed: the same source tree always hashes the same, so building the same agent twice yields one file, not two. The filename sanitizes the hash's `sha256:` colon to a hyphen (`sha256-abcdef...agent`) for filename portability, matching the pull cache.
- **`refs/`** maps a reference to a bundle. Each `@org/name:tag` is a small file at `refs/<registry>/<repository>/<tag>` whose contents are the `files_hash` it points at. Tags are cheap pointers: several can point at one bundle, and a bundle can have none.

This split is why removing a tag does not always delete bytes, and why one bundle can appear under many names. `ls` reports the pairing, `rm` respects it.

## store ls

Lists every bundle in the store, one row per reference it is tagged under, plus a row for any bundle stored only by content hash. Takes no arguments.

```
mcpvessel store ls [--json]
```

The default output is a three-column table:

- **REFERENCE**: the `@org/name:tag` the bundle is indexed under, or `<untagged>` for a bundle no tag points at.
- **HASH**: the first 12 hex characters of the `files_hash`, with the `sha256:` prefix stripped.
- **SIZE**: the `.agent` file size, rendered in B, KB, MB, or GB.

A bundle with two tags produces two rows sharing one hash and size. A bundle with no tag produces one `<untagged>` row. Rows are sorted by reference, then by hash. An empty store (no `bundles/` directory yet) prints just the header.

| Flag | Meaning |
| --- | --- |
| `--json` | Emit the entries as indented JSON instead of the table. Each object has `Ref` (empty for an untagged bundle), `Hash` (the full `sha256:`-prefixed files hash), and `Size` (bytes). |

## store load

Verifies a `.agent` file and adds it to the store, so you can run it or depend on it via `USES` without pulling it from a registry. Takes exactly one file argument.

```
mcpvessel store load FILE [-t REF]
```

What it does, in order:

1. **Parses the tag** if you passed `-t`. The reference must carry a version tag; `-t @okedeji/researcher` with no `:version` is rejected before anything is written.
2. **Verifies integrity.** The bundle is extracted to a throwaway temp directory and its source tree is re-hashed against the manifest's `files_hash`. A registry pull is digest-verified by the OCI client; a loose `.agent` file is not, so this is where a corrupt or truncated bundle is caught before it enters the store. This is an integrity check, not an authenticity one: it catches accidental damage and a tamper that left the manifest untouched, but an attacker who rewrites `files_hash` to match their edit defeats it. Only a signature would not, and a loose file carries none. A bundle with an empty `files_hash` is a pre-hash format with nothing to check, and passes.
3. **Copies the file into `bundles/`** at the path for its `files_hash`. Loading the same bundle twice overwrites the same file, so it is idempotent.
4. **Tags it** if you passed `-t`, writing the ref file so `run @org/name:tag` and a parent's `USES` find it by name. Without `-t` the bundle is addressable only by its content hash, which the load line prints.
5. **Seeds the pull cache.** It computes the bundle's OCI manifest digest (deterministic, no network) and writes the bytes into `~/.mcpvessel/cache` under that digest. This is what lets a parent built against the loaded bundle resolve it offline, with no registry round trip.

On success it prints `Loaded <file> as <name>`, where `<name>` is the reference when you tagged it, or the bare `files_hash` when you did not.

| Flag | Meaning |
| --- | --- |
| `-t`, `--tag REF` | Index the loaded bundle under this reference (`@org/name:version`). A version tag is required; a bare name is rejected. Without it the bundle is addressable only by its content hash. |

## store rm

Removes one or more bundles from the store, by reference or content hash. Takes one or more arguments.

```
mcpvessel store rm REF|HASH...
```

Each argument is classified before it is removed. An all-hex string of six or more characters (optionally `sha256:`-prefixed) is treated as a **content hash**; anything carrying an `@`, `/`, or `:` is parsed as a **reference**. The two paths differ in what they delete:

**A reference** (`@org/name:tag`) removes that one tag. The bundle's bytes go with it only when no other reference still points at them; if another tag shares the bundle, the file stays and the removal says so. A reference with no version tag is rejected, and a tag that is not in the store reports `<ref> is not in the store`.

**A content hash** (or a unique prefix of one) removes the bundle file and every reference that pointed at it. A prefix that matches more than one bundle is rejected as ambiguous rather than guessing; a prefix that matches none reports that no bundle has that hash.

Arguments are processed left to right, and a failure on one does not stop the rest: the error is printed to stderr as `<arg>: <reason>` and the loop continues to the next. After the batch, if any argument failed, the command exits non-zero with `failed to remove N of M`. Successes are printed to stdout as they happen.

The messages spell out the outcome:

- `Removed <ref> and its bundle` when the tag was the last pointer and the bytes went too.
- `Removed <ref> (bundle kept; another reference still points at it)` when the tag went but the bundle stayed.
- `Removed bundle <hash> and N reference(s): <list>` when a hash removed a bundle that had tags.
- `Removed bundle <hash>` when a hash removed an untagged bundle.

`rm` touches only the local store. A copy you pushed to a registry is untouched. Emptied ref directories (the last tag under an org, say) are pruned so no empty scaffolding is left behind.

`store rm` has no flags.

## Examples

```sh
# See what is in the store.
mcpvessel store ls

# Load a bundle a teammate handed you and name it, so run and USES find it.
mcpvessel store load researcher.agent -t @okedeji/researcher:0.1

# Load a bundle without naming it; it is addressable by the printed content hash.
mcpvessel store load researcher.agent

# Remove one tag; its bytes go too if no other tag shares them.
mcpvessel store rm @me/oncall:0.1

# Remove several at once, mixing references and a content hash.
# A missing one is reported but does not stop the others.
mcpvessel store rm @me/a:0.1 @me/b:0.1 353c68abb588
```

## Notes

- `ls` prints a bare hex hash (no `sha256:` prefix), and `rm` accepts that same bare form: it restores the `sha256:` prefix internally before matching. So you can copy a hash out of `ls` and paste it straight into `rm`.
- The line between a reference and a hash is purely lexical. A short, all-hex string of six or more characters is read as a content hash even though it could in principle be a repository name; a real reference always carries an `@`, `/`, or `:` and so is never all-hex.
- Removing a bundle by hash also removes every tag pointing at it, which is the fast way to purge an agent that got tagged several times. Removing by reference is surgical: one tag, and the bytes only if they are now orphaned.
- `load` verifies integrity, not identity. It catches corruption and casual tampering, but does not prove who built the bundle. For provenance, pull a signed copy from a registry (see [pull](pull.md)) rather than loading a loose file.
- `load -t` requires a version tag. The rejection message references `import -t` rather than `store load -t`, but the constraint is the same: give the reference a `:version`.
- Everything here is a plain file operation under `~/.mcpvessel`. There is no daemon to be running and no network to reach; `ls`, `load`, and `rm` work the same whether or not the runtime is up.

## See also

- [build](build.md): what writes bundles into the store in the first place.
- [import](import.md): wrap a server and build it into the store in one step.
- [run](run.md), [call](call.md), [serve](serve.md): use a bundle once it resolves locally by reference.
- [push](push.md), [pull](pull.md): move a bundle between the store and an OCI registry. `load` is the offline counterpart to `pull`, for a `.agent` file handed to you directly.
- [Ship it](../README.md#ship-it): the push and pull round trip a `load` bypasses.
