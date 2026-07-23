# login

Store credentials so mcpvessel can authenticate to a registry. `login` has two targets that share a command but not a mechanism: an **OCI registry** (where `push` and `pull` move bundles), whose credentials go into the shared Docker credential store, and **`mcp-registry`** (where `register` publishes public agents), which runs GitHub's device flow and caches a registry bearer under `~/.mcpvessel`.

```
mcpvessel login [REGISTRY | mcp-registry] [flags]
```

`login` takes at most one argument. The literal word `mcp-registry` is reserved and selects the MCP Registry path. Anything else is an OCI host. With no argument at all, it logs in to the default OCI host.

## Logging in to an OCI registry

This is the path `push` and `pull` need. It writes a username and password into the credential store that every OCI tool on your machine reads, so once you are logged in here, `docker`, `oras`, and mcpvessel all see the same credential for that host.

**Which host.** With an argument, the host is that argument (`ghcr.io`, `registry.acme.internal`). With no argument, the host is the mcpvessel default: `VESSEL_REGISTRY` if set, otherwise `ghcr.io`. This is the same default your `@org/name` shorthand references resolve to, so `login` with no argument authenticates exactly the host your shorthand pushes to.

**Where the credential goes.** `login` opens the Docker credential store (`credentials.NewStoreFromDocker`), the same `~/.docker/config.json` plus any configured credential helper. Because the store is shared, two things follow: a credential you store here works for any registry tool that reads it, and if you already logged in to this host with `docker login` (or a helper already holds the credential), you do not need this command at all.

**Plaintext fallback on a bare host.** The store is opened with plaintext puts allowed. On a machine with a credential helper configured, the helper stores the secret as usual. On a machine with no helper (a bare Linux box or a CI runner), rather than refuse the login, it falls back to writing base64 into `config.json`, matching Docker's own default behavior. This only changes the no-helper case; a helper, where present, still wins.

`credentials.Login` validates the credential against the registry before it stores it, so a wrong password fails here, not later on the first push. On success `login` prints `Logged in to <host>` to stdout.

### How credentials are read

`login` resolves the username and password without prompting first, and only prompts for whatever is still missing.

**Non-interactive, from flags and stdin.** If you pass `--password-stdin`, the password is read from stdin (all of it, with a trailing newline trimmed). In this mode `--username` is required and `--password` must not also be set, so a piped login is fully specified: `-u NAME --password-stdin < token.txt`. If instead you pass both `-u` and `-p` on the command line, those are used directly. Either way, nothing is prompted.

**Interactive, prompting for the rest.** If a piece is still missing (no `--password-stdin`, and username or password unset), `login` prompts for the missing ones. The `Username:` and `Password:` prompts are written to stderr so stdout stays clean. The password prompt reads without echo when stdin is a real terminal (your typing is hidden); when stdin is a pipe or a test buffer it reads a plain line instead of blocking on a terminal that will never answer.

After resolving, if either username or password is still empty, `login` fails with `username and password are required`.

## Logging in to the MCP Registry

`mcpvessel login mcp-registry` proves the GitHub identity you publish under and caches a registry bearer that `register` later reads. There is no anonymous publish: this always ends with a real token or an error.

It resolves a GitHub token, exchanges it for a registry bearer, and saves the bearer. How it gets the GitHub token depends on what you give it:

**A token you feed it (the CI path).** If you pipe a token with `--password-stdin`, or pass one with `-p`, that token is used directly and no browser or OAuth app is involved. Feed a GitHub PAT owned by the namespace's user and CI publishes without any interactive step. `--username` is ignored here: identity comes from the token, not a name you type. As on the OCI path, `--password` and `--password-stdin` cannot be combined.

**The device flow (interactive).** With no token supplied, `login` runs GitHub's OAuth device flow. It requests a device code, prints `Open <url> and enter code: <code>` to stderr, and polls GitHub until you authorize in the browser or the attempt expires. It honors GitHub's stated poll interval, backs off on `slow_down`, waits through `authorization_pending`, and gives up at GitHub's own deadline with `authorization timed out; run 'mcpvessel login mcp-registry' again`. The requested scope is `read:user`, the minimum to read your login name, nothing about repositories or organizations.

The device flow needs a registered GitHub OAuth app client id in `VESSEL_GITHUB_CLIENT_ID`. Without it, and without a piped token, `login` fails and tells you both ways out: set the client id with `mcpvessel config env set VESSEL_GITHUB_CLIENT_ID <client-id>`, or feed a GitHub token with `--password-stdin`.

**Exchange and cache.** The GitHub token is POSTed to the MCP Registry's `/v0.1/auth/github-at` endpoint, which returns the registry's own bearer and an expiry. The registry is `https://registry.modelcontextprotocol.io`, or `VESSEL_MCP_REGISTRY` if you override it. The bearer is written to `~/.mcpvessel/mcpregistry-token.json` at mode `0600` (`VESSEL_HOME` overrides the `~/.mcpvessel` root). On success `login` prints `Logged in to the MCP Registry`.

`register` reads that saved token; an expired one is treated as not logged in, so re-run `login mcp-registry` to refresh it.

## Flags

| Flag | Meaning |
| --- | --- |
| `-u`, `--username NAME` | Registry username. Required with `--password-stdin` on the OCI path. Ignored on the `mcp-registry` path (identity comes from the GitHub token). |
| `-p`, `--password TOKEN` | Password or token on the command line. Prefer `--password-stdin` to keep it out of your shell history and the process table. Cannot be combined with `--password-stdin`. |
| `--password-stdin` | Read the password (OCI) or GitHub token (`mcp-registry`) from stdin, trailing newline trimmed. On the OCI path also requires `--username`. |

## Examples

```sh
# Log in to GHCR with a token piped from a file (no prompt, nothing in history).
mcpvessel login ghcr.io -u okedeji --password-stdin < token.txt

# Log in to the default host, prompting for username and a hidden password.
mcpvessel login

# Authenticate to the MCP Registry interactively via GitHub's device flow.
mcpvessel login mcp-registry

# Authenticate to the MCP Registry in CI with a GitHub PAT, no OAuth app needed.
mcpvessel login mcp-registry --password-stdin < gh-token.txt

# Log in to a private registry, prompting only for the password.
mcpvessel login registry.acme.internal -u ci
```

## Notes

- The two targets do not share storage. An OCI login lands in the Docker credential store; an MCP Registry login lands in `~/.mcpvessel/mcpregistry-token.json`. Logging in to one does not authenticate the other.
- You often do not need the OCI path at all. If `docker login` (or a credential helper) already holds the host's credential, `push` and `pull` reuse it.
- `--password` puts the secret on the command line, where it can leak into shell history and the process table. Prefer `--password-stdin`, or let `login` prompt (the password prompt hides your typing on a terminal).
- The plaintext fallback only applies when no credential helper is configured. It exists so `login` works on a bare host or CI runner instead of refusing; a machine with a helper keeps using it.
- The saved MCP Registry bearer expires. `register` treats an expired token as not logged in, so run `login mcp-registry` again when publishing starts failing with an auth error.
- The device flow needs network to GitHub and to the MCP Registry, and a browser you can open to enter the code. On a headless CI host, use the `--password-stdin` token path instead.

## See also

- [push](push.md): pushes a bundle to the OCI registry this command authenticates.
- [register](register.md): publishes to the MCP Registry using the bearer `login mcp-registry` caches.
- [import](import.md): builds the bundles you then push and register.
- [Ship it](../README.md#ship-it): the push-and-share flow login sits in front of.
