# pull

Download an agent bundle someone pushed to an OCI registry into your local cache, so you can `run`, `call`, or `serve` it by reference. `pull` fetches the bundle, checks its signature against the publisher key you have pinned for that namespace, writes it to a content-addressed file, and prints the path. It is the read side of `push`: what one person builds and ships, another pulls and runs, caged the same way.

```
mcpvessel pull REF [flags]
```

You rarely need `pull` on its own. `run`, `call`, and `serve` pull a missing bundle for you. Reach for `pull` when you want to prime the cache ahead of time, confirm a reference resolves and verifies, or capture the resolved digest and cache path for a script.

## What a REF can be

`REF` names the bundle to fetch. It takes the same forms `push` does, and it must be pinned to something concrete: a version tag or a digest. A bare name with neither is rejected before any network call, with a message showing the tag form.

**Shorthand** (`@org/name:version`): resolves to the default registry, `ghcr.io`, and a repository of `org/name`. `VESSEL_REGISTRY` overrides the default host. The org is required, so `@name:1.0` (no slash) is an error.

**A fully-qualified host ref** (`host/org/name:tag`): the first path segment is taken as the registry host when it looks like one (it contains a dot or a port colon), for example `ghcr.io/okedeji/researcher:0.1`. A name whose first segment does not look like a host and is not shorthand is ambiguous and rejected, with a message telling you to write `@org/name` or `host/org/name`.

**A digest pin** (`@org/name@sha256:...` or `host/org/name@sha256:...`): pins the exact bytes. The digest must be a real `sha256:` digest. When both a tag and a digest appear, the digest wins.

**An MCP Registry name** (`io.github.org/server`): resolved through the MCP Registry index the same way `run` and `serve` resolve it. The entry's OCI artifact is what gets pulled, at the version the entry records, or at a `:version` you append to override it. This is the one REF form that does not need an explicit tag or digest, since the registry entry supplies the version.

## The cache and digest pinning

A pulled bundle lands under `~/.mcpvessel/cache/bundles/` as `sha256-<hash>.agent`, named by the manifest digest with the colon rewritten to a hyphen for filename portability. `VESSEL_HOME` moves the whole state root, so the cache follows it to `$VESSEL_HOME/cache`. The write is atomic: the bytes go to a `.tmp` file and are renamed into place, so an interrupted pull never leaves a half-written bundle that a later run would mistake for a cache hit.

The cache is digest-addressed and immutable, which makes one shortcut safe: **a digest-pinned REF whose bytes are already cached returns immediately, with no network access and no signature re-check.** The signature was verified when those bytes were first ingested, and the digest guarantees they have not changed since. A tag REF does not take this path. A tag can move, so `pull` always resolves it over the network to learn the digest it points at now, fetches, verifies, and writes the cache, even when the resulting bytes were already there.

## What a pull does

For a REF that is not already cached by digest, `pull`:

1. **Resolves the manifest.** It opens the repository with your stored registry credentials (from `mcpvessel login`) and resolves the tag or digest to a manifest, then reads the manifest and finds the bundle layer by its media type. A manifest with no bundle layer is not an mcpvessel bundle, and the pull fails saying so. The manifest's digest becomes the bundle's cache key.
2. **Verifies the signature** (see below) before anything touches the cache. Ingest is the one boundary where signature policy holds, so verification happens here, not at run time.
3. **Writes the cache** atomically and returns the path.

On success and without `--json`, `pull` prints three lines to stdout, then the cache path on its own line:

```
1.2.0: Pulling from ghcr.io/anthropic/web-search
Digest: sha256:...
Status: Downloaded bundle for ghcr.io/anthropic/web-search:1.2.0
/Users/you/.mcpvessel/cache/bundles/sha256-....agent
```

That last line is the whole point: it is a path you can hand straight to `mcpvessel run` or `mcpvessel call`.

## Signature verification

Every network pull passes through one signature gate at cache ingest. What happens depends on whether the bundle is signed and whether you have seen its publisher before.

A signature, when present, lives as a small OCI artifact tagged next to the bundle by the cosign convention: the bundle's digest `sha256:abc` becomes the tag `sha256-abc.sig`. Any OCI registry can hold it, no referrers API required. `pull` looks for that tag.

**Unsigned bundle.** If no signature artifact is published, the pull normally proceeds and you are told, on stderr:

```
Signature: none (unsigned bundle)
```

Set `VESSEL_REQUIRE_SIGNATURES` to a truthy value (anything other than empty, `0`, or `false`) and this fails closed instead: an unsigned bundle is refused, with a message naming the variable and telling you to unset it or ask the publisher for a signed push. Strict mode is the switch for an environment that trusts only signed artifacts.

**Signed, first time you have seen this publisher.** The signature is checked against the pulled digest and the repository name it was signed for. A signature is bound to both, so it cannot be lifted onto different bytes or replayed under another publisher's name. If it verifies, its key is pinned for that publisher's namespace and recorded, and you are told, on stderr:

```
Signature verified; pinned signing key a1b2c3d4e5f6 for ghcr.io/okedeji (first use)
```

The fingerprint is the first twelve hex characters of the key's SHA-256.

**Signed, publisher already pinned, same key.** The common case. The signature verifies and its key matches the pin, so the pull proceeds with:

```
Signature verified (key a1b2c3d4e5f6)
```

**Signed, publisher pinned, different key.** The pull fails closed. This is the case the whole scheme exists to catch:

```
SIGNING KEY MISMATCH for ghcr.io/okedeji: bundle is signed by key <new> but key <pinned> was pinned 2026-01-04.
The publisher may have rotated keys, or this artifact is not from them.
If you have verified the new key out of band, run 'mcpvessel trust rm ghcr.io/okedeji' and pull again
```

Nothing is written to the cache when verification fails.

All of these notices go to **stderr**. The progress lines, the digest, the status, and the cache path go to **stdout**, so a script can capture the useful output cleanly while the human-readable signature notices stay on the error stream.

## Trust on first use (key pinning)

`pull` pins publisher keys the way SSH pins host keys in `known_hosts`. The first verified key you see for a namespace is trusted and remembered; a different key for that same namespace later fails closed rather than being accepted silently. This trades a formal certificate authority for a simple, local guarantee: after the first pull, you are running the same publisher you ran before, or you find out.

The unit of trust is a **scope**: the registry host plus the first path segment of the repository, the namespace one publisher controls. `ghcr.io/okedeji/researcher` and `ghcr.io/okedeji/oncall` share the scope `ghcr.io/okedeji` and therefore one pinned key. Pins live in `~/.mcpvessel/trust.json` (mode `0600`). A missing file is an empty store; a malformed file fails closed rather than dropping every pin. Inspect and edit pins with `mcpvessel trust`; the mismatch error above tells you the exact `trust rm` to run when a publisher has legitimately rotated keys and you have confirmed the new one.

Integrity of the bytes is a separate job, handled by the digest. The signature and pin answer "who published this," not "did it arrive intact."

## JSON output

`--json` replaces the human-readable stdout (the "Pulling from", "Digest", "Status", and path lines) with a single JSON object:

```json
{"ref":"ghcr.io/anthropic/web-search:1.2.0","digest":"sha256:...","path":"/Users/you/.mcpvessel/cache/bundles/sha256-....agent"}
```

`ref` is the canonical `host/repository[:tag|@digest]` form, `digest` is the resolved manifest digest, and `path` is the cache file. The signature notices still print, to stderr, so `--json` output stays parseable while the pin-and-verify story is still visible.

## Flags

| Flag | Meaning |
| --- | --- |
| `--json` | Emit a machine-readable JSON object (`ref`, `digest`, `path`) on stdout instead of the progress lines. Signature notices still go to stderr. |

## Examples

```sh
# Pull a signed bundle by shorthand and version.
mcpvessel pull @anthropic/web-search:1.2.0

# Pull from an explicit host and org.
mcpvessel pull ghcr.io/okedeji/researcher:0.1

# Pull by MCP Registry name; the entry supplies the OCI artifact and version.
mcpvessel pull io.github.okedeji/mcpvessel-docs

# Pin exact bytes by digest; if already cached, returns offline with no re-verify.
mcpvessel pull @okedeji/researcher@sha256:9f8e...

# Capture the cache path for a script, keeping notices off stdout.
BUNDLE=$(mcpvessel pull @anthropic/web-search:1.2.0 --json | jq -r .path)

# Refuse anything unsigned.
VESSEL_REQUIRE_SIGNATURES=1 mcpvessel pull @anthropic/web-search:1.2.0
```

## Notes

- A digest-pinned pull that hits the cache does no signature check, because the bytes were verified when first ingested and the digest proves they are unchanged. Verification runs on every network pull.
- A tag pull always goes to the network to resolve the tag, even when the resolved bytes are already cached, because a tag can move.
- The first pull from a publisher pins whatever key it presents. Trust on first use protects against later substitution, not against a bad first key. On a fresh machine, the safest first pull is one whose publisher fingerprint you can check out of band.
- `pull` needs credentials only for a private repository. It uses whatever you stored with `mcpvessel login`; a public repository pulls without any.
- The mismatch, unsigned-in-strict-mode, and not-a-bundle failures all leave the cache untouched. A failed pull never poisons the cache.
- `pull` fetches a finished bundle. It does not build, introspect, or run anything. Signature verification proves who published the bytes and that they are intact, not that the caged server inside is safe to run.

## See also

- [push](push.md): the other half, signing and uploading a bundle to a registry.
- [login](login.md): store the registry credentials a private pull needs.
- [run](run.md), [call](call.md), [serve](serve.md): use a bundle by reference; each pulls it for you if the cache is cold.
- [import](import.md): wrap a server or compose an agent, then push and pull the result.
- [Ship it](../README.md#ship-it): the push-and-pull round trip in context.
- [SECURITY.md](../SECURITY.md#signing-and-trust): the signing and trust model in full.
