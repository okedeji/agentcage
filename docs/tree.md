# tree

Print the full transitive `USES` tree of an agent: every sub-agent it pulls, every sub-agent those pull, down to the leaves. Each dependency is pulled by its locked digest, cache-first, the same walk a `run` uses to resolve the tree, so what `tree` prints is exactly what would execute. This is the audit surface for `BAN`: it names every agent that will run by the `@org/name` you would write into a `BAN` directive to forbid one anywhere in the subtree.

```
mcpvessel tree BUNDLE|REF
```

`tree` takes exactly one argument and no flags of its own. It reads bundles, pulls missing dependencies into your store, and writes to stdout. It never runs an agent and never boots a cage.

## What the argument can be

The single argument resolves the same way it does for `run`, `call`, and `inspect`. Four forms, tried in order.

**A local `.agent` file.** If the argument is a path to an existing file (not a directory), it is used as-is. Its display label in the output is the path you passed.

**A bare content hash.** `sha256:<hex>`, the form `build` prints for an unnamed bundle. A full hash or a prefix (at least six hex characters) is looked up in your store. A prefix that matches two bundles fails with "content hash is ambiguous in the store"; a hash that matches none fails with "no bundle with that content hash in the store". Nothing is pulled: a bare hash is store-only.

**An MCP Registry name** (reverse-DNS, e.g. `io.github.okedeji/researcher`). The name is resolved against the MCP Registry to the OCI reference its entry points at, then treated as a reference below. An entry with no OCI artifact fails with "MCP Registry entry has no OCI artifact to pull".

**A registry reference** (`@org/name:version` or `name@sha256:...`). A reference must carry a version tag or a digest; a bare `@org/name` fails with "a version tag or digest is required". The reference is resolved store-first: if your store already has that bundle it is used without a network call, otherwise it is pulled from the registry. Signature notices during a pull go to stderr, so they do not mix into the tree on stdout.

Whatever the form, the result is one local `.agent` file, the root of the tree.

## How the tree is resolved

`tree` reads the root bundle's manifest, then walks its `USES` graph. For each `USES` edge:

- The edge must carry a **locked digest**. `build` pins every `USES` to the exact content it resolved and rejects cycles at build time. If a `USES` has no digest, `tree` stops with "has no locked digest; rebuild the bundle so the runtime can pull by digest". It never falls back to the mutable tag.
- The dependency is **pulled by that digest**, cache-first: the store is consulted before the registry, so a tree you have run before resolves offline. A pull failure stops the walk with "pulling USES ...".
- A sub-agent reached by two parents is **pulled and printed once per unique (name, digest)**. Two different pins of the same name stay distinct; the same pin shared by two callers dedupes to one node, though the edge to it is drawn from each caller.

The walk is the same resolver a `run` uses, so the tree is a faithful preview of what a run would boot, not a separate best-effort read.

## Reading the output

The first line is the root's display label. The line under it, indented, is the root's one-line glance (see below). Then the `USES` edges, drawn as an indented tree with `├─` and `└─` branches:

```
@okedeji/researcher:0.1
  model=anthropic/claude-sonnet-4  budget=$1.00  egress=allow:api.anthropic.com  tools=1
├─ fetch  @okedeji/fetch  sha256:a1b2c3d4e5f6  DENY delete
│    egress=allow:*  tools=3
└─ search  @okedeji/brave-search  sha256:0f1e2d3c4b5a
     secrets=[BRAVE_API_KEY]  tools=2
```

Each edge line is the **alias** (the last path segment of the `USES` ref, the local name the parent calls the sub-agent by), then the sub-agent's **label**: `@org/name` plus the first twelve characters of its locked digest as `sha256:...`. That label is exactly the `@org/name` you write into a `BAN`. If the edge carries `USES ... DENY tool,tool`, those denied tools are appended as `DENY ...`; `DENY` scopes a block to that one edge, blocked by the MCP gateway on that hop only.

Under each sub-agent is its glance line, and under that its own `USES` edges, recursively.

**Glance fields.** The glance is the agent's operational summary, only the parts it declares, space-separated:

- `model=` the reasoning model, if it has one.
- `budget=$` the spend cap in USD, if set.
- `resources=` cage limits as `cpu=,mem=,pids=`, only the parts declared.
- `egress=` the `EGRESS` line verbatim (e.g. `allow:host` or `allow:*`).
- `env=[...]` declared `ENV` keys, sorted; a required key (empty default) is marked with a trailing `*`.
- `secrets=[...]` declared `SECRETS` names.
- `tools=N` the count of externally visible tools (the `MAIN` and any `PUBLIC` tools; internal tools are not counted).

Full per-agent detail lives in `inspect`; the glance is deliberately one line.

**Cycles.** The build resolver rejects cycles, so a well-formed bundle has none. As a safety net against a malformed bundle, if the walk reaches an agent already on the current path, that edge prints `(cycle)` and does not recurse, instead of looping forever.

## Baseline memory

After the tree, `tree` prints the always-on memory a run of it would hold:

```
Baseline memory (always-on): ~1.5GiB
  Elastic sub-agents activate on demand, bounded by cages.max_live.
```

The estimate counts only what is up for the whole run, not the sub-agents that activate on demand:

- The **root cage**, sized by its `RESOURCES` memory hint or the runtime default.
- The **MCP gateway**, once, if the tree has any `USES` edge.
- A **reasoning gateway**, once, if any agent in the tree declares a model.
- An **egress gateway**, once, if any agent declares egress hosts.
- Each **egress sub-agent's cage**: a sub-agent that reaches the network is always-on, because the egress proxy keys it by a stable IP, so its cage counts toward the baseline. Non-egress sub-agents are elastic and are not counted.

`cages.max_live` bounds how many elastic sub-agents run at once, which is why the elastic tail is not in the baseline figure.

## Bans

If the root manifest declares any `BAN`, `tree` lists them last:

```
Bans (declared here, applied across the whole subtree):
  @okedeji/scraper
  @okedeji/fetch ONLY delete,put
```

A `BAN` with no tools forbids the whole agent anywhere in the subtree; a `BAN` with tools (printed as `ONLY tool,tool`) forbids just those tools on every edge that reaches that agent, however deep. This is the point of pairing the ban block with the tree: the tree lists every agent that would run, by the same `@org/name` label a `BAN` uses, so you can see what to forbid and confirm a ban already in place covers what you meant.

`BAN` (root-declared, whole-subtree) is not `DENY` (one `USES` edge). `DENY` shows inline on its edge in the tree; `BAN` shows in this block.

## Flags

`tree` has no flags. It takes exactly one argument, `BUNDLE|REF`. Passing zero or more than one argument is an error from the argument check before anything runs.

## Examples

```sh
# Audit a local bundle before you serve it.
mcpvessel tree researcher.agent

# Audit a bundle by its registry reference (store-first, pulled on a miss).
mcpvessel tree @okedeji/researcher:0.1

# Audit a bundle you know only by the content hash build printed.
mcpvessel tree sha256:a1b2c3d4e5f6

# Audit a server straight from the MCP Registry by its reverse-DNS name.
mcpvessel tree io.github.okedeji/researcher
```

## Notes

- `tree` may pull. Resolving a reference you do not have locally, or a `USES` dependency missing from your store, pulls it from the registry into your store. A bare content-hash argument is the exception: it is store-only and never pulls.
- The output is a preview, not a run. `tree` boots no cages, creates no networks, and spends no budget. The baseline memory line is an estimate from the manifests, not a measurement.
- A `USES` without a locked digest means a stale bundle. Rebuild it with `build` so every dependency is pinned, then re-run `tree`.
- The digests in the labels are the locked ones from the manifest, truncated to twelve characters for reading. They identify the exact content that would run, not a mutable tag.
- Run `tree` after editing a `BAN` to confirm the label you forbade matches an agent actually in the subtree. A `BAN` on a name that never appears silently protects nothing.

## See also

- [inspect](inspect.md): full detail for one agent, where the tree glance is only a summary.
- [run](run.md): boots this same digest-locked tree; `tree` previews what it would start.
- [build](build.md): locks every `USES` to a digest and rejects cycles, which is what makes the walk exact.
- [import](import.md): composes servers under a reasoning agent that `USES` them, the trees `tree` renders.
- [VESSELFILE.md](VESSELFILE.md): the `USES`, `DENY`, and `BAN` directives this view reads.
- [Give it a brain](../README.md#give-it-a-brain): composing agents with `USES`, the graph `tree` walks.
