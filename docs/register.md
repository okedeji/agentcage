# register

Publish a public agent's metadata to the MCP Registry without re-pushing its bytes. `register` takes an agent already sitting on a public OCI host, reads the bundle's manifest, and records a `server.json` entry in the official MCP Registry so the agent is discoverable by its reverse-DNS name. `mcpvessel push` does this for you on a public host; `register` is the same publish on its own, for an agent you pushed before logging in to the registry, or one whose OCI bytes have not changed and so does not need another push.

```
mcpvessel register REF [BUNDLE] [flags]
```

## register versus push

`push` uploads a bundle to an OCI registry and, when that host is public and you are logged in, publishes the registry entry in the same step. `register` skips the upload entirely. It assumes the bytes are already on a public host and only moves the metadata. Two cases where you reach for it:

- You pushed the agent before you had run `mcpvessel login mcp-registry`, so the push uploaded the bytes but skipped the publish. `register` publishes now, no re-push.
- The OCI bytes have not changed since the last push, so there is nothing to upload again, but you want to publish or re-publish the entry (a first publish, a corrected namespace).

The registry stores metadata only. Each entry's package points at the OCI artifact; `register` never moves an agent's bytes, so the artifact must already be pushed and publicly pullable (see [The public-artifact gate](#the-public-artifact-gate)).

## REF and BUNDLE

`REF` (required) names the pushed artifact: a full OCI reference like `ghcr.io/okedeji/researcher:0.1`, or the `@org/name:version` shorthand, which resolves to your default registry (`ghcr.io` unless `VESSEL_REGISTRY` overrides it). A version tag is required. A ref with no tag is rejected before anything else runs, because the tag becomes the published entry's version and the package identifier.

`BUNDLE` (optional) is the path to the `.agent` file whose manifest supplies the entry's description and any eval stamp. `register` finds the bundle in this order:

1. The positional `BUNDLE` argument, if given.
2. Otherwise the `-b`, `--bundle` flag.
3. Otherwise the bundle in your local store indexed by `REF`.

If none of those resolve to a bundle (no path given and nothing in the store for that ref), `register` errors and tells you to build the ref first or pass a path. The positional argument wins over the flag when both are present.

## The reverse-DNS name

An MCP Registry entry is keyed by a reverse-DNS name like `io.github.okedeji/researcher`. `register` derives it from `REF` when the ref is a GHCR reference: `ghcr.io/<owner>/<name>` becomes `io.github.<owner>/<name>`. Only GHCR maps, because GitHub is the namespace ownership `mcpvessel login mcp-registry` proves. Any other host, or a repository path deeper than `owner/name`, does not derive a name.

- **`--name io.github.<user>/<server>`** publishes under a namespace you name explicitly. Use it when the ref is not GHCR, or to publish under a namespace different from the one the ref implies.
- With no `--name` and a ref that does not derive a name, `register` errors and asks you to pass `--name`, rather than publishing under a guessed namespace.

## The public-artifact gate

Before it publishes, `register` proves the artifact is anonymously pullable. It resolves `REF` against the OCI host with no credentials: an anonymous pull token succeeds only on a public repository. If the resolve fails (the bytes were never pushed, or the package is private), `register` refuses and tells you to run `mcpvessel push` first and make the package public. The registry indexes a pointer to your bytes; this gate keeps it from advertising a pointer that anyone following it would fail to pull.

## What a registered entry advertises

`register` reads the bundle's manifest and builds the `server.json` the registry stores:

- **`name`**: the reverse-DNS name (derived or `--name`).
- **`version`**: the tag from `REF`.
- **`description`**: the Vesselfile's `META description`, or `mcpvessel agent <name>` when the manifest carries none, clamped to the registry's 100-character ceiling.
- **`packages[0]`**: a single OCI package. Its `registryType` is `oci`, its `identifier` is `<host>/<repo>:<tag>` (the registry wants an OCI package's version inside the identifier, not the version field), and its transport type is `stdio`.
- **`$schema`**: the registry's server schema URI, which publish rejects the record without.

### The publisher-provided _meta nesting

Everything mcpvessel records rides inside one namespace, `io.modelcontextprotocol.registry/publisher-provided`, the single free-form `_meta` slot a publisher may set. A sibling top-level `_meta` key outside the registry's own namespaces is rejected on publish with a 422 "unexpected property". Inside that slot `register` writes:

- **`tool`**: always `mcpvessel`, marking who published the entry.
- **`evals`**: the manifest's eval stamp, when the bundle carries one.
- **`imported_from`**: the wrapped server's canonical identity, when the bundle is an imported wrapper (from the Vesselfile's `imported_from` meta).

## Authentication

`register` requires a live MCP Registry token, obtained with `mcpvessel login mcp-registry` (GitHub's device flow, which proves you own the GitHub namespace you publish under). A missing login is an offer to log in, not a silent skip:

- A valid, unexpired token: `register` proceeds.
- No registry app configured (`VESSEL_GITHUB_CLIENT_ID` unset): `register` errors, telling you to set the client id with `mcpvessel config env set`.
- An interactive terminal with the app configured but no token: `register` runs the login device flow inline, then publishes.
- A non-interactive session with no token: `register` errors, telling you to run `mcpvessel login mcp-registry` first. It never prompts in a script.

The publish request carries the bearer token per call. A rejected token is an error, never a silent no-op: a 401 tells you to log in again, a 403 tells you the token cannot publish that namespace.

## Flags

| Flag | Meaning |
| --- | --- |
| `-b`, `--bundle PATH` | Path to the `.agent` file whose manifest supplies the entry's description and eval stamp. Default: read from the store by `REF`. A positional `BUNDLE` argument overrides this flag. |
| `--name NAME` | MCP Registry reverse-DNS name to publish under (`io.github.<user>/<server>`). Default: derived from a GHCR `REF`. Required when the ref is not GHCR or does not derive a name. |

## Examples

```sh
# Publish a GHCR bundle already pushed and public. Name derives to
# io.github.okedeji/researcher.
mcpvessel register ghcr.io/okedeji/researcher:0.1

# Publish under an explicit namespace.
mcpvessel register @okedeji/researcher:0.1 --name io.github.okedeji/researcher

# Publish reading the manifest from a specific .agent file.
mcpvessel register ghcr.io/okedeji/researcher:0.1 -b ./researcher/out.agent

# You pushed before logging in; log in, then publish on its own.
mcpvessel login mcp-registry
mcpvessel register ghcr.io/okedeji/researcher:0.1
```

## Notes

- `register` does not push. If the bytes are not already on the host, the public-artifact gate fails; run `mcpvessel push` first.
- The version tag is load-bearing: it is both the entry's `version` and the tail of the package identifier. A digest-only ref (no tag) is rejected up front.
- Publishing the same name and version again re-publishes the entry. Use it to correct a description or namespace without touching the bytes.
- The description comes from the bundle's manifest, not from `REF`. To change what the entry advertises, rebuild the bundle with a new `META description`, push it, and register again.
- `register` reads the token from `~/.mcpvessel/mcpregistry-token.json` (mode 0600). A missing file is "not logged in", not an error.

## See also

- [push](push.md): pushes the bytes and, on a public host, publishes in the same step; `register` is that publish on its own.
- [import](import.md): build and cage a server into the bundle you later push and register.
- [login](login.md): `mcpvessel login mcp-registry`, the GitHub device flow that authorizes publishing.
- [search](search.md): find published entries by reverse-DNS name or keyword.
- [Ship it](../README.md#ship-it): pushing and running a caged agent by reference.
