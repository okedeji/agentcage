# Troubleshooting

The failures you are most likely to hit, what they mean, and the command that fixes each. Every quoted message below is the real one, so you can search this page for what your terminal said.

## The daemon

**`the daemon is not running; start it with 'mcpvessel init'`.** Most commands need the control-plane daemon and this is how they fail without one. `mcpvessel init` starts it (and is a fast no-op when the runtime is already prepared). You normally never start the daemon by hand: any command that needs it spawns one, so seeing this usually means the daemon was stopped or its socket is not where the CLI is looking (see `VESSEL_HOME` below).

**`warning: the daemon is running a stale mcpvessel build; restart it with 'mcpvessel daemon stop && mcpvessel init'`.** You rebuilt or upgraded mcpvessel while a daemon from the old build kept running. Nothing is broken yet, but the two disagree on code. Run the restart it names.

**Something went wrong and you want the daemon's own story.** Its output lands in `~/.mcpvessel/daemon.log`. The startup and shutdown timeout errors point there too.

## First run on macOS

**`init` seems slow.** The first `init` on a Mac downloads a Linux VM image and boots a rootless container runtime inside it, which takes two to five minutes on a normal connection. It narrates its phases while it works. Every run after that is seconds.

**The runtime seems wedged (`stats unavailable (is the runtime up?)`, boots that hang).** The VM can be rebuilt from scratch without touching your bundles, secrets, or config:

```sh
mcpvessel daemon stop
mcpvessel init --recreate
```

## A tool call fails on a blocked host

A run is deny-default: the first time a caged server reaches a new host, the connection does not open. This is the cage working, not an outage. What you see depends on how the run started:

- **In a foreground `run` or `call`**, the connection is held and you get an inline prompt: answer `y` and the same call continues.
- **Behind `serve`**, the call fails fast instead, and the tool error names the blocked host and the approve command. Approve it, and the client's retry passes.

`mcpvessel egress ls` shows what is held or was denied, each with its approve command; `mcpvessel egress allow <target> <host>` approves and remembers it, so the next run does not ask. A host you did not expect is the thing to look hard at before approving. [egress](egress.md) covers the whole model.

## Reasoning runs

**`a reasoning agent needs an LLM provider: run 'mcpvessel config provider set'`.** Reasoning agents call a model through the LLM gateway, and the gateway needs a configured provider and key. `mcpvessel config provider set` stores one; the key stays with the gateway and never enters a cage.

**`402 over-budget: the run's LLM budget is spent`.** The run hit its spend cap, which is the cap doing its job. Raise it on a live run with `mcpvessel budget set <run> <usd>`, or start the next run with a bigger `--budget`.

## Pull and signing

**`SIGNING KEY MISMATCH for <scope> ...`.** The bundle is signed with a different key than the one pinned on your first pull from that publisher. Either the publisher rotated keys or the artifact is not from them. Do not clear the pin until you have verified the new key's fingerprint out of band; then the error itself names the `mcpvessel trust rm` to run.

**An unsigned bundle is refused.** You have `VESSEL_REQUIRE_SIGNATURES` set, which fails unsigned pulls closed. Unset it, or ask the publisher for a signed push. Without the variable, an unsigned pull proceeds with a `Signature: none (unsigned bundle)` notice.

## Serving beyond your machine

**`serving on <addr>, which is not loopback: the front door has NO authentication, so anyone who can reach this address can call every exposed agent. Bind 127.0.0.1, or put TLS and auth in front of it.`** The warning says it all: the `--listen` address is the exposure decision. Keep it on `127.0.0.1` unless a proxy in front of it is doing TLS and auth.

## Paths and state

**Commands cannot find the daemon, or two terminals see different state.** `VESSEL_HOME` relocates the whole state root (socket, store, config, logs) off `~/.mcpvessel`. The CLI and the daemon must agree on it, so a command run with `VESSEL_HOME` set will not find a daemon started without it, and vice versa.

**The daemon refuses to start over a too-long socket path.** A Unix socket path has a hard OS cap, and a deep `VESSEL_HOME` can exceed it. The error states the length and the limit; point `VESSEL_HOME` at a shorter path.

## Windows

There is no native Windows binary. mcpvessel runs inside WSL2: install the Linux binary in your WSL2 distro and run everything there, the CLI, the daemon, and `~/.mcpvessel` all inside the distro. From Windows, reach a served endpoint at the address WSL2 exposes to the host.

## Starting over

To remove mcpvessel entirely, or to reset a broken install to factory state, see [Uninstall](init.md#uninstall). The short version: `mcpvessel daemon stop`, remove the binary, then delete `~/.mcpvessel`.

## See also

- [daemon](daemon.md): what the control plane owns and how it starts and stops.
- [init](init.md): the one-time runtime setup, `--recreate`, and uninstall.
- [egress](egress.md): the deny-default model behind blocked hosts.
- [SECURITY.md](../SECURITY.md): reporting an actual vulnerability, as opposed to a breakage.
