# push

Upload a built `.agent` bundle to an OCI registry so a teammate can pull and run it by reference. `push` uploads the bundle bytes, signs the pushed digest with this host's key, and (on a public host) advertises the agent's metadata to the MCP Registry. Pulls verify the signature and pin your key, so what a teammate runs is exactly what you built, caged the same way.

```
mcpvessel push REF [BUNDLE] [flags]
```

## REF and where the bundle comes from

`REF` is the agent reference and must carry a version tag. A push with no tag is refused (`a version tag is required`), because an untagged artifact is not something a teammate can pull back by name.

- **Shorthand** (`@org/name:version`) resolves to the default registry, GHCR (`ghcr.io`).
- **Fully qualified** (`ghcr.io/org/name:version`, `docker.io/...`, a private host) is taken as written.

The bundle bytes come from your local store by default. `mcpvessel build -t REF` put the bundle there, and `push` reads it back by the same ref. If the store has no bundle for the ref, the push fails and tells you to build it first or pass a path.

To push a file built elsewhere, or one built with `build -o` (never indexed in the store), give an explicit bundle path. Two ways, equivalent:

```sh
mcpvessel push @me/researcher:0.1 ./researcher.agent     # positional BUNDLE
mcpvessel push @me/researcher:0.1 -b out/researcher.agent  # -b / --bundle
```

The positional `BUNDLE` wins over `-b` when both are given.

## Order of operations

`push` does its work in a fixed order so a failure never leaves a half-published agent:

1. **Parse the ref and resolve the bundle path** (store or explicit file).
2. **Decide publication and log in, before the upload.** An unpublishable `--public` push fails here, before any bytes move, and the short-lived registry token is minted just before it is used. See [MCP Registry publication](#mcp-registry-publication).
3. **Stamp evals** into the manifest if `--with-evals` is set. See [Recording evals](#recording-evals-with---with-evals).
4. **Push the OCI artifact** (the bundle blob plus its manifest) and get back the manifest digest.
5. **Sign the digest** and upload the signature next to the bundle, unless `--no-sign`. See [Signing](#signing).
6. **Publish to the MCP Registry** if step 2 decided to, now that the bytes are actually up.

Signing and publish happen only after the OCI artifact is up, so a failure in either never leaves a registry entry or a signature pointing at bytes that are not there.

## What gets pushed

The OCI upload writes, under `REF`:

- The **bundle blob**, the `.agent` file's bytes.
- An **OCI manifest** over that blob, marked with the artifact type `application/vnd.mcpvessel.bundle.v1`. Its `created` annotation is pinned to the bundle's `built_at`, not wall clock, so the manifest digest is a deterministic function of the bundle bytes. Pushing the same bundle twice produces the same digest.
- For a GHCR ref, an **ownership marker**. The reverse-DNS server name (`io.github.<owner>/<name>`) is stamped as a manifest annotation and, because the MCP Registry reads it from the image config's labels, as a labeled config blob. This is what lets the registry confirm the artifact belongs to the name it is published under.

Unless `--no-sign`, signing then adds a **signature artifact**: a signature blob (`application/vnd.mcpvessel.signature.v1+json`) and a manifest over it, tagged under the signed digest with the cosign convention. `sha256:abc...` becomes the tag `sha256-abc....sig`, so any plain OCI registry can hold it with no referrers API.

## Signing

Every push signs by default. The signature is ed25519 over the pushed manifest digest plus the repository it was pushed to (`ghcr.io/org/name`), so a valid signature cannot be replayed onto other bytes or under another publisher's name.

The signing key lives at `~/.mcpvessel/signing-key.json` (honoring `VESSEL_HOME`). On the first signed push, `push` generates and persists one and prints its fingerprint and path with a reminder to back it up:

```
Generated signing key ab12cd34ef56 at ~/.mcpvessel/signing-key.json (back it up; 'mcpvessel keys' shows the public half)
```

On success it prints `Signed: key <fingerprint>`. To sign as the same publisher from several machines (a laptop and CI), export the key on one and import it on the others rather than letting each generate its own. See [keys](keys.md).

**Signing failure fails the push.** If the signature cannot be produced or uploaded, the command returns an error, even though the bundle bytes are already up. The error notes this and points at the escape hatch: `the bundle is pushed; --no-sign pushes without a signature`. A signature you asked for must not silently not happen.

**`--no-sign`** pushes without signing. Pulls of an unsigned bundle report it as unsigned rather than verifying a key, and a puller who has set `VESSEL_REQUIRE_SIGNATURES` will refuse it (see below).

### How pulls use the signature

A pull verifies the signature at cache ingest, the one boundary every network pull crosses:

- A **signed** bundle must verify against the pulled digest and repository, and its key must match the one pinned for the publisher's scope (`ghcr.io/<owner>`). The first verified pull pins the key (SSH `known_hosts` semantics). A later pull signed by a different key fails closed with a mismatch error and the `mcpvessel trust rm` remedy.
- An **unsigned** bundle passes with a notice, unless the puller has set `VESSEL_REQUIRE_SIGNATURES` to a truthy value (anything other than empty, `0`, or `false`), in which case the pull fails closed asking for a signed push.

This is a pull-side policy. `push` only decides whether a signature exists to be checked. See [SECURITY.md](../SECURITY.md#signing-and-trust) and [trust](trust.md).

## MCP Registry publication

On a public OCI host, `push` also advertises the agent's metadata (its `server.json`) to the MCP Registry, so it is discoverable by name. This is metadata only; the bundle bytes live in the OCI registry.

**Whether it publishes** is decided before the upload:

- `--private` skips publication, even on a public host. A note is printed.
- `--public` forces an attempt, even on a host not auto-detected as public.
- Otherwise, a known public host (`ghcr.io`, `docker.io`, `quay.io`) attempts and any other host skips with `note: skipping MCP Registry publish (private OCI host)`.

**Login happens before the upload too.** When a publish is going to be attempted, `push` ensures a live MCP Registry token first, so the token is fresh when used and an operator who needs to log in is not surprised after the bytes are already up. In an interactive session with no token it offers to log in; declining pushes without publishing and prints how to `register` later. In a non-interactive session it never prompts: it publishes if a token is present, otherwise skips with a note (or, under `--public`, fails, since a forced publish that cannot happen is an error). If no MCP Registry app is configured (`VESSEL_GITHUB_CLIENT_ID` unset), publication cannot proceed; `--public` fails, otherwise it skips with a note.

**The published name** defaults to `io.github.<owner>/<name>`, derived from the GHCR ref. `--name` overrides it to publish under a different reverse-DNS namespace. A ref with no derivable name (any non-GHCR host, or a repository path deeper than `owner/name`) errors rather than publishing under a guessed namespace, so pass `--name` there.

**The publish is gated on the bytes being publicly pullable.** Before recording metadata, `push` confirms the artifact resolves with no credentials. If it does not (not pushed, or the package is still private), publication refuses rather than advertise a dangling pointer.

**A publish failure after the bytes are up is a warning, not a push failure**, unless `--public` was passed: `warning: pushed to OCI but MCP Registry publish failed`. The bundle is already pushed, so only an explicit `--public` (where the operator demanded publication) turns the failure into a non-zero exit. Re-publish later with [register](register.md), which does the metadata step on its own.

## Recording evals with --with-evals

`--with-evals` runs the bundle's eval suite and records the results into the manifest before the push, so pulled bundles carry a transparency signal of how they scored.

It reads the bundle's declared `EVAL` suite. A bundle that declares none fails the flag (`bundle REF declares no EVAL suite`). It runs the suite against the resolved bundle path (a `-b` bundle not indexed in the store still evaluates), prints a summary, and stamps the report into the manifest. `--judge-model PROVIDER/MODEL` picks the model that grades judged cases; left unset, your default provider is used.

Failing cases do not block the push. The stamp is a transparency signal, not a gate: after a run with failures it prints `warning: N of M cases failed; pushing anyway` and proceeds. See [eval](eval.md).

## Authentication

OCI authentication reuses your stored registry credentials from the shared credential store (the same one Docker uses). A prior `mcpvessel login` against the host, or any tool's login that wrote to that store, is enough. `push` does not take a username or password; it reads what is already stored. An unreadable credential store is an error, not a silent fall-through to anonymous access. MCP Registry publication uses a separate token from `mcpvessel login mcp-registry`, handled as described above.

## Flags

| Flag | Meaning |
| --- | --- |
| `-b`, `--bundle PATH` | Path to a `.agent` file to push, instead of reading it from the store by ref. A positional `BUNDLE` argument, if given, overrides this. |
| `--no-sign` | Push without signing. Pulls will report the bundle unsigned, and a puller with `VESSEL_REQUIRE_SIGNATURES` set will refuse it. |
| `--with-evals` | Run the bundle's `EVAL` suite and record the results into the manifest before pushing. Fails if the bundle declares no suite. Failing cases warn but do not block the push. |
| `--judge-model PROVIDER/MODEL` | With `--with-evals`, the model that grades judged cases. Default: your default provider. |
| `--public` | Attempt MCP Registry publication even on a host not auto-detected as public, and make a publish failure fail the push. |
| `--private` | Skip MCP Registry publication even on a public host. |
| `--name NAME` | MCP Registry name to publish under. Default: `io.github.<owner>/<name>` derived from a GHCR ref. Required for a ref with no derivable reverse-DNS name. |
| `--json` | Emit machine-readable JSON (`ref`, `tag`, `digest`, and `signing_key` when signed) on stdout. Human notes go to stderr. |

`--public` and `--private` are opposite intents; pass at most one.

## Examples

```sh
# Push a bundle from the store, signing it, publishing to the MCP Registry if the host is public.
mcpvessel push @okedeji/researcher:0.1

# Push a file built elsewhere, addressed by a fully-qualified ref.
mcpvessel push ghcr.io/okedeji/researcher:0.1 -b out/researcher.agent

# Push to a private host without touching the MCP Registry, unsigned.
mcpvessel push registry.internal/team/researcher:0.1 --private --no-sign

# Run the eval suite and stamp the results into the manifest before pushing.
mcpvessel push @okedeji/researcher:0.1 --with-evals --judge-model anthropic/claude-3-5-sonnet

# Push and get the digest back as JSON for a script.
mcpvessel push @okedeji/researcher:0.1 --json
```

## Notes

- Pushing the same bundle twice yields the same manifest digest, because the manifest's `created` annotation is pinned to the bundle's `built_at`. This lets a locally locked `USES` digest stay valid across a later push.
- The bundle blob and signature blob are skipped if the registry already has them, so a re-push of unchanged bytes only rewrites the tag.
- Publication advertises metadata; it never uploads bytes. The bytes must already be pushed and anonymously pullable, which is why publish runs after the OCI upload and checks public reachability first.
- Keep one signing key across your machines. If each machine generates its own, teammates who pinned one key will hit a mismatch on a pull signed by another. Use `mcpvessel keys export` on one machine and import it on the rest.
- `push` requires a version tag. A digest-pinned or bare ref will not do, since a push has to write a tag a teammate can pull by.

## See also

- [build](build.md): build the `.agent` bundle `push` uploads, and put it in the store with `-t REF`.
- [pull](pull.md), [run](run.md), [serve](serve.md): the other side, fetching and running a pushed bundle, where signatures are verified.
- [register](register.md): publish (or re-publish) an already-pushed bundle's metadata to the MCP Registry on its own.
- [login](login.md): store OCI credentials, and log in to the MCP Registry for publication.
- [keys](keys.md), [trust](trust.md): manage this host's signing key and the publisher keys your pulls have pinned.
- [eval](eval.md): the suite `--with-evals` runs and stamps.
- [Ship it](../README.md#ship-it) and [SECURITY.md](../SECURITY.md#signing-and-trust): the push-and-pull workflow and the signing model.
