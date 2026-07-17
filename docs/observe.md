# observe

Learn which hosts a server actually reaches. `observe` serves one bundle with its cage in audit mode: every outbound host is allowed and recorded instead of blocked. You point your MCP client at the printed URL, exercise the tools you use, and when the window ends `observe` prints the exact `EGRESS allow:` line to bake in, so you do not have to guess a server's egress before locking it down.

```
mcpvessel observe BUNDLE [flags]
```

`observe` records, it does not lock anything down. It never edits the bundle. After it reports the hosts, you add the line to the Vesselfile and rebuild (or re-import with `--egress`) yourself. It is the standalone form of `import --observe-egress`, run against a bundle you already have.

## What BUNDLE can be

The single argument names the agent to watch. It resolves the same way `serve` resolves a target.

- **A tag or reference** (`@me/github:0.1`, a content hash): passed through to the daemon, which locates it in your store.
- **A source directory** containing a `Vesselfile`: resolved by content hash. If a matching bundle is already in your store (an earlier `import` or `build` introspected it), that bundle is served as is. If not, the directory is built into the store first. The directory's name becomes the agent's address, since a hash prefix would make a poor one.

Before serving, `observe` prepares the container images the bundle needs, so the first tool call does not stall on an image pull.

## Audit mode

Normally a cage is deny-default: the in-run CONNECT proxy refuses any host the bundle's `EGRESS allow:` policy does not name. `observe` serves with that proxy flipped to audit mode. Every host the server reaches is allowed through and recorded, the first time it is seen, as a line the proxy writes into the run's log:

```
egress observed: api.github.com (agent github)
```

The proxy filters on the CONNECT host without terminating TLS, so it never holds a secret or sees a payload. It learns hostnames, nothing more. The agent name in parentheses lets a multi-cage bundle (an agent that `USES` sub-servers) attribute each host to the cage that reached it.

Because audit mode allows everything, the server runs with full outbound network during the window. This is a deliberate, temporary opening to profile the server, not a sandbox. Run it against a server you are willing to let reach the internet for the length of the window.

## The window

`observe` records for a fixed window, then reports and exits.

- `--for 90s` sets the window explicitly.
- With no `--for` (or `0`), it uses the configured default from `mcpvessel config serve set --observe-seconds`, which falls back to 60 seconds when unset.

Ctrl-C is meant to end the window early. The window otherwise runs to its full length even if you finish exercising the tools sooner, so set `--for` to something short when you know the server well, or long when you need time to drive it.

When the window closes, the front door is torn down (every served agent is stopped) before `observe` returns, whether it ended on the timer, early, or with an error.

## Reaching the server during the window

While the window is open, `observe` prints where to drive the server. It serves on `--listen` (default `127.0.0.1:7300`, loopback only, so the audit-mode front door never touches the network) and prints one MCP endpoint per served agent:

```
Observing egress in audit mode on 127.0.0.1:7300 for 1m0s (Ctrl-C ends early).
Point your MCP client at the URL below and exercise the tools you use; every host it reaches is recorded.
  http://127.0.0.1:7300/agents/github/mcp
```

It also prints a plain-HTTP form, so you can drive a tool with `curl` and no MCP client at all:

```
Plain HTTP works too, no MCP client needed:
  curl -X POST http://127.0.0.1:7300/agents/github/tools/<tool> -d '{"arg": "value"}'
```

Whatever a tool reaches while you exercise it goes through the audit-mode proxy and lands in the log. A server whose tools you never call records nothing, so drive the tools you actually intend to use in production.

## The report

When the window ends, `observe` reads the logs of the instances the run spawned, collects every `egress observed:` host, dedupes and sorts them, and prints the line to bake in:

```
Observed egress:
  EGRESS allow:api.github.com,uploads.github.com
Add that line to the agent's Vesselfile and run 'mcpvessel build <dir>', or re-import with --egress api.github.com,uploads.github.com.
```

That `EGRESS allow:` line is exactly what the Vesselfile expects. Paste it in and rebuild, and the cage goes back to deny-default with those hosts allowed.

If nothing was observed, there is no line to print:

```
No outbound hosts observed. If nothing exercised its tools during the window, re-run and drive them (--for extends the window); if the server truly needs no network, leave it deny-default.
```

An empty result means one of two things: you did not exercise the tools during the window (re-run and drive them, extending `--for` if you need more time), or the server genuinely needs no network, in which case leaving it deny-default with no `EGRESS` line is correct.

## Inputs the server needs to boot

A server that needs a key or config value just to start has to have it during observe, since the agent boots to serve its tools. These flags mirror `run` and `serve`.

- **`--secret NAME`** supplies a secret, resolved from your environment first, then the mcpvessel secret store. The value never appears on the command line. If it is in neither place, observe fails and tells you to store it with `mcpvessel secrets set NAME`. Prefix `agent:NAME` to scope a secret to one cage of a multi-cage bundle.
- **`--env KEY=VALUE`** supplies a plain config value. `--env KEY` (no value) passes it through from your environment.
- **`--secret-file`** and **`--env-file`** read many at once, one `NAME=VALUE` (or `agent:NAME=VALUE`) per line, `#` comments and blank lines ignored.

## Flags

| Flag | Meaning |
| --- | --- |
| `--listen ADDR` | Address to serve the agent on during the window. Default `127.0.0.1:7300`, loopback. |
| `--for DURATION` | How long to record before reporting, e.g. `90s`. `0` (the default) uses the configured window, which itself defaults to 60 seconds. |
| `--secret NAME` | Supply a secret the server needs to boot, resolved from your environment or the secret store. `agent:NAME` scopes it to one cage. Repeatable. |
| `--secret-file PATH` | Read secret values (`[agent:]NAME=VALUE` per line) from a permissions-restricted file. |
| `--env KEY=VALUE` | Supply an env value the server needs to boot, or `KEY` to pass it through from your environment. Repeatable. |
| `--env-file PATH` | Read env values (`KEY=VALUE` per line) from a file. |

## Examples

```sh
# Watch a stored bundle for 90 seconds, then report its egress.
mcpvessel observe @me/oncall:0.1 --for 90s

# Profile a server that needs a key to boot.
mcpvessel observe @me/github:0.1 --secret GITHUB_PERSONAL_ACCESS_TOKEN

# Observe a source directory. It is built into the store first if needed.
mcpvessel observe ./github --for 2m

# Serve the audit front door on a different port.
mcpvessel observe @me/github:0.1 --listen 127.0.0.1:8080
```

## Notes

- `observe` changes nothing. It does not touch the bundle, the Vesselfile, or its stored egress policy. Acting on the report (paste the line, rebuild) is up to you.
- The report is only as complete as your exercise of the tools. A host a tool reaches only on a code path you never trigger will not appear. Drive the tools the way production will.
- The window runs on a wall clock, not on idle. It does not stop early because the server went quiet, only when `--for` elapses (or on Ctrl-C).
- Audit mode allows all outbound traffic for the length of the window. This is intended for profiling a server you are about to cage, not for running one you do not trust.
- `observe` needs the daemon running, like the other run and serve commands.
- To profile at import time instead, `import --observe-egress` builds the bundle, runs this same audit window, and rewrites `EGRESS` and rebuilds for you in one step.

## See also

- [import](import.md): `--observe-egress` runs this same audit window during an import and writes the result back for you.
- [serve](serve.md): serve a bundle for real, with its cage enforcing (not auditing) egress.
- [build](build.md): rebuild a Vesselfile after you paste in the `EGRESS allow:` line.
- [config](config.md): `serve set --observe-seconds` sets the default window.
- [secrets](secrets.md): store the keys a server needs to boot.
- [Cage it](../README.md#cage-it): the audit-mode walkthrough in context.
- [VESSELFILE.md](VESSELFILE.md): the `EGRESS allow:` directive the report produces.
