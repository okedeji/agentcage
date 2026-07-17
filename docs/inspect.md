# inspect

Show what an agent is before you run it. `inspect` prints the parsed Vesselfile, build metadata, and tool catalog of a bundle without launching it. Point it at a local `.agent`, a published OCI reference, or a content hash and it reads the sealed manifest. Point it at a reverse-DNS MCP Registry name and it shows that entry's catalog (its packages, the inputs it declares, whether it can be caged) without pulling anything, so you can see what an MCP needs before you import it.

```
mcpvessel inspect BUNDLE|REF [--json]
```

`inspect` is read-only. It never touches the daemon and changes nothing on disk, except that resolving an OCI reference the store lacks pulls the bundle into your store (the same cache every other command shares).

## What a BUNDLE|REF can be

The single argument selects one of four forms, discriminated by shape, and each resolves differently.

**A local `.agent` file.** An existing path (anything `stat` finds that is not a directory) is read in place. Nothing is resolved or fetched. The `Bundle:` line echoes the path you gave.

**A bare content hash**, the form `build` prints for an unnamed bundle: `sha256:` followed by six or more hex characters. It is matched against the store by prefix, so `sha256:abc123` finds the full-length bundle it prefixes. A hash with no bundle in the store is an error (`no bundle with that content hash in the store`); a content hash is never pulled, only looked up locally. A digest-pinned reference (`name@sha256:...`) is not this form, since the `@` hides the digest behind a name.

**An OCI registry reference**, `@org/name:version` or a digest pin. It resolves store-first: if your store already has the bundle it is read from there, otherwise it is pulled from the OCI registry into the store and read. A reference must carry a tag or a digest; a bare name with neither is an error. During a pull, signature-verification notices print to stderr, leaving stdout clean for `--json`.

**A reverse-DNS MCP Registry name** (`io.github.user/server`, `com.example/weather`): a dotted namespace, exactly one slash, no tag, no digest, no `@`. This is the one form `inspect` treats specially. Instead of resolving to a bundle it looks the name up in the MCP Registry and prints the catalog entry (see [Registry entry view](#registry-entry-view)). It pulls nothing. This is deliberate and differs from `run` and `call`, which resolve the same name to its OCI package and pull it: `inspect` is the step you take to vet a server before you commit to importing it.

## The manifest view

For any bundle form, `inspect` reads the manifest sealed into the `.agent` at build time and prints a header, the Vesselfile, the tool catalog, dependencies, and eval status. The header:

```
Bundle:       researcher.agent
Spec version: 0.1
Built:        2026-02-14T10:04:11Z with mcpvessel 0.4.2
Files hash:   sha256:...
Cage memory:  ~512 MiB
```

`Built:` appears only when the manifest carries a build timestamp. `Files hash:` pins the source tree the bundle was built from. `Cage memory:` is the memory the agent's `RESOURCES mem` asks for, or the default agent cap when it declares none. It is the author's advisory hint, not the enforced ceiling, which the operator sets at serve time.

## The Vesselfile block

Under `Vesselfile:` `inspect` prints the parsed directives, each on its own line, in a fixed order. Only directives the bundle actually carries are shown.

- `FROM` and `ENTRYPOINT` always print.
- `RUN` prints once per build step.
- `MODEL` prints when set (`provider/name`).
- `MAIN` prints when set. A tool collection has no `MAIN`, so its absence tells you the bundle is a collection you `call` rather than an agent you `run`.
- `EXPOSE` prints its tools comma-joined.
- `BUDGET` prints the per-run USD cost cap.
- `RESOURCES` prints the `cpu= mem= pids=` hint.
- `EGRESS` prints the allow rule verbatim, the exact hosts the cage may reach.
- `SECRETS` prints the secret names the agent injects at run time.
- `ENV` prints one `KEY=VALUE` per line, sorted.
- `META` prints one `key value` per line, sorted.
- `EVAL` prints the eval suite path.

The human view leaves out a few manifest fields that exist only for machines: the exec-form entrypoint argv, the `BAN` list, and the `OPTIONAL` input names. To see those, use `--json`.

## Tools and visibility

Under `Tools:` `inspect` lists every tool the agent declares, one per line, each with a compact signature, its visibility, and its description:

```
Tools:
  search(query: string, depth?: string)   public   Web search over an index.
  fetch(url: string)                       private  Fetch a URL's contents.
```

The signature comes from the tool's captured input schema. A `?` marks a non-required parameter. A tool with a schema but no properties shows `()`. A tool whose schema was never captured (a declared-only catalog) shows no signature at all. The full JSON schemas are verbose and their shape is not final, so the human view omits them; `--json` includes them.

Visibility is the access gate, and the catalog lists all three levels so a reviewer sees the entire capability surface:

- `main` is the tool `mcpvessel run` invokes. Callable from outside the cage.
- `public` tools are callable from outside the cage, by name, with `mcpvessel call`.
- `private` tools are listed for audit but only the agent itself can call them. Listing one does not make it reachable.

## Uses

When the agent depends on sub-agents, `inspect` prints them under `Uses:`, one per dependency:

```
Uses:
  @me/fetch:0.2 [public] sha256:... DENY delete,purge
```

The reference and version come first. `[public]` marks a dependency the agent re-exposes to its own callers. The `sha256:` digest is the lockfile: the digest the tag resolved to at build time, so the daemon pulls the pinned bytes even if the tag is later re-pushed. A pre-resolver bundle carries no digest and the daemon falls back to the tag. `DENY` lists the sub-agent tools this edge forbids; an empty deny accepts every tool the sub-agent exposes.

## Evals

When the bundle carries eval status, `inspect` prints it:

```
Evals:
  suite       evals/researcher.yaml
  status      declared, never run
```

`suite` is the `EVAL` directive. `status` reads `declared, never run` for a suite that was declared at build time but never executed. Once a full suite runs, it reads the counts instead, for example `47 passed, 3 failed  judge 0.83  last run 2026-02-14T11:00:00Z`. The judge score and last-run stamp appear only when present.

## Registry entry view

When the argument is a reverse-DNS name, `inspect` resolves it against the MCP Registry and prints the catalog entry rather than a manifest:

```
Registry entry: io.github.modelcontextprotocol/filesystem
Description:    Local filesystem access over MCP.
Version:        1.2.0
Repository:     https://github.com/modelcontextprotocol/servers
Evals:          47/50 j0.83

Package:        oci ghcr.io/modelcontextprotocol/filesystem@1.2.0 (stdio)
  inputs:
    ROOT_DIR    (required)  Directory the server may read.
    API_TOKEN   (secret)    Upstream API token.

Import it with: mcpvessel import io.github.modelcontextprotocol/filesystem
```

`Description`, `Version`, `Repository`, and `Evals` print only when the entry carries them. `Evals` is the stamped signal an mcpvessel-published wrapper leaves, rendered compact (`passed/total`, plus `jN.NN` when a judge scored it, or just `declared`); a server nobody published through mcpvessel has none.

Each `Package:` line names the ecosystem, identifier, version, and transport. Only `stdio` packages can be wrapped into a cage. When a package declares inputs, they list under `inputs:`, each tagged `(secret)` or `(required)`, with its description. These are exactly the values `import` will write into the generated Vesselfile as `SECRETS` and `ENV`, so this is where you learn what an MCP needs to boot before you import it.

The footer tells you how to act on the entry. An entry with at least one package closes with the `import` command to cage it. An entry with only remotes (a hosted endpoint, no code to run) closes with the remote-only note instead: `This is a remote MCP server; it cannot be imported into a cage. Reach it from an agent that declares EGRESS allow:<host> and its SECRETS.` A cage contains a process, and there is no process to contain in a hosted URL.

## --json

`--json` emits the raw record instead of the rendered view, for piping into `jq` or a script.

- For any bundle form, it encodes the full manifest, indented: everything the human view shows plus the fields it omits (each tool's complete input schema, the exec-form entrypoint argv, the `BAN` list, the `OPTIONAL` input names).
- For a registry name, it encodes the entry's `server.json` record exactly as the MCP Registry returned it.

Pull-time signature notices go to stderr, so `--json` stdout stays a clean document even on a cache miss.

## Flags

| Flag | Meaning |
| --- | --- |
| `--json` | Emit the raw record as indented JSON: the full manifest for a bundle, or the `server.json` entry for a registry name. Off by default (the rendered human view). |

## Examples

```sh
# Inspect a local bundle you just built.
mcpvessel inspect researcher.agent

# Inspect a published bundle by reference (pulled into the store if absent).
mcpvessel inspect @anthropic/web-search:1.2.0

# See what an MCP declares before importing it (no pull).
mcpvessel inspect io.github.modelcontextprotocol/filesystem

# Read the full manifest, schemas and all, as JSON.
mcpvessel inspect researcher.agent --json | jq '.tools[].name'
```

## Notes

- A reverse-DNS name and an OCI reference behave differently on purpose. `inspect io.github.user/server` shows the registry catalog and pulls nothing; `inspect @org/server:1.0` resolves and pulls a bundle. Use the name form to vet a server before importing, the reference form to inspect something already published as an mcpvessel bundle.
- A bare content hash is looked up in your store by prefix and never pulled. Six hex characters is the minimum, which keeps a `sha256:` typo from scanning the whole store. A miss is an error.
- An OCI reference must carry a tag or a digest. A bare `@org/name` is rejected before any network call.
- `inspect` is read-only and daemon-free. The only side effect is that pulling an OCI reference the store lacks caches the bundle, exactly as `run`, `call`, and `tree` would.
- Tool JSON schemas, the `BAN` list, the `OPTIONAL` inputs, and the exec-form entrypoint appear only under `--json`. The human view stays scannable.
- `Cage memory` is the author's `RESOURCES` hint or the default cap, not the enforced limit. The operator sets the real ceiling when serving.
- A private tool in the catalog is auditable, not callable. Only `main` and `public` tools are reachable from outside the cage.

## See also

- [import](import.md): turn a registry entry `inspect` shows you into a caged bundle.
- [VESSELFILE.md](VESSELFILE.md): the directives the manifest view prints, defined in full.
- [build](build.md), [serve](serve.md), [run](run.md), [call](call.md): produce a bundle, then serve or invoke it.
- [Cage it](../README.md#cage-it) and [Commands](../README.md#commands): where `inspect` sits in the workflow.
