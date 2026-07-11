# mcpvessel

**Cage untrusted MCP servers, keep using them, compose them into agents, and share them.**

[![CI](https://github.com/okedeji/mcpvessel/actions/workflows/ci.yml/badge.svg)](https://github.com/okedeji/mcpvessel/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/okedeji/mcpvessel?include_prereleases&sort=semver)](https://github.com/okedeji/mcpvessel/releases)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)

<!-- DEMO GIF GOES HERE: docs/demo.gif -- the 30-second "malicious server tries to steal keys, gets blocked" recording -->

An MCP server runs as a subprocess with your full user permissions. Nothing in the protocol sandboxes it, so a server you install can read your SSH keys, your cloud credentials, and your `.env` files, run commands on your machine, and send any of it anywhere. This is not hypothetical: connecting to an untrusted MCP server has already produced remote code execution on the host ([CVE-2025-6514](https://nvd.nist.gov/vuln/detail/CVE-2025-6514), rated critical), and audits keep finding thousands of public servers with exploitable flaws. A server that is safe today can also ship a malicious update tomorrow, so vetting one once is not enough.

mcpvessel runs MCP servers in isolated containers instead: no host access, no outbound network unless you allow it, and no provider keys inside the sandbox. It brings its own runtime, so there is no Docker or container engine to install. The same tool can also compose several caged servers into an LLM agent and distribute them over an OCI registry, both covered below.

> **Status: pre-1.0** (`v0.1.0-rc.x`). It works, but the CLI surface may still change between releases. Pin a release if you need something stable. See [supported versions](SECURITY.md#supported-versions).

## Contents

- [Cage it](#cage-it)
- [Give it a brain](#give-it-a-brain)
- [Ship it](#ship-it)
- [What the cage actually does](#what-the-cage-actually-does)
- [What it does not protect against](#what-it-does-not-protect-against)
- [How it works, briefly](#how-it-works-briefly)
- [Install](#install)
- [Requirements](#requirements)
- [Uninstall](#uninstall)
- [Commands](#commands)
- [Contributing and support](#contributing-and-support)
- [License](#license)

## Cage it

On macOS or Linux:

```sh
brew install --cask okedeji/tap/mcpvessel
mcpvessel init
```

Put the MCP servers you use behind one caged endpoint:

```sh
mcpvessel import npm:@modelcontextprotocol/server-github pypi:mcp-server-time
mcpvessel serve --listen 127.0.0.1:7000 ./server-github ./mcp-server-time
```

That prints one URL. Point Claude, Cursor, or any MCP client at it:

```
http://127.0.0.1:7000/mcp
```

Every server's tools appear together on that single URL, and your client calls them exactly as before. Each server runs in its own container on its own network: no host access, no outbound network it did not request, no provider keys, and no route to the other servers. A compromised server is isolated from the rest and from your machine.

It accepts any MCP server from npm, PyPI, or a container image, whether or not it is in a registry. One server or several, the commands are the same.

## Give it a brain

A caged server exposes tools for an MCP client like Claude to call, so your client does the thinking. Add `--reasoning` and the thinking moves inside the cage: the same servers become one agent that takes a goal and decides which tools to call, and in what order, on its own. You turn a set of MCP servers into an agent with one flag, and write no agent code:

```sh
mcpvessel import io.github.getsentry/sentry-mcp io.github.brave/brave-search-mcp-server --reasoning -t @me/oncall:0.1
mcpvessel run @me/oncall:0.1 "what is causing our top Sentry error this week, and how do I fix it?"
```

This wraps both servers and runs an LLM tool-use loop over them, caged alongside them, with a per-run spend cap. The result is an agent you invoke like any other, and the servers stay sandboxed as before.

It does not have to live in your terminal. Serve it and it is an HTTP endpoint you can hit with nothing but `curl`:

```sh
mcpvessel serve --listen 127.0.0.1:7000 @me/oncall:0.1
curl -sX POST 127.0.0.1:7000/agents/oncall -d '{"prompt":"what is causing our top Sentry error, and how do I fix it?"}'
# {"result": "..."}
```

No MCP client, no SDK, just JSON in and JSON out. The same agent can sit on a server, run in a CI job, or live behind your own API. It still speaks MCP on that port for clients that prefer it, and any single tool is directly callable at `POST /agents/<name>/tools/<tool>`.

## Ship it

A caged server or agent is a content-addressed bundle. Push it to any OCI registry:

```sh
mcpvessel push @me/oncall:0.1
```

A teammate pulls and runs it, sandboxed the same way, without importing or building it themselves:

```sh
mcpvessel run @me/oncall:0.1 "..."
```

It is signed on push and verified on pull, so they run exactly what you built, caged the same way.

## What the cage actually does

Three things, and they are the whole point.

**No network unless you allow it.** A caged server starts with the internet switched off. If it genuinely needs to reach `api.github.com`, you say so, and that becomes the only place it can go. It can't phone home, and it can't ship your data anywhere you didn't approve.

**Your keys can't leak out.** A server that needs a credential to do its job, a GitHub token or a database password, gets only the ones it declared, and nothing else. It can use that key to reach the one API you allowed, but it can't send the key, or your data, anywhere else. Reaching an unknown server is off by default, and it stays off until you deliberately turn it on.

**Each server is on its own.** Caged servers can't see each other, and they can't see your host. One bad server can't reach the good ones sitting next to it.

To be clear about what this is: mcpvessel contains what a server can *do*. It doesn't read the server's code or vet the package for you. That is the point, though. You don't have to trust the code if it can't reach your files, your network, or your keys anyway.

## What it does not protect against

Being honest about the edges, because a security tool that overpromises is worse than one that doesn't:

- **It does not vet code.** It contains what a server can reach, not what its code says. A caged server is free to misbehave inside its cage; it just can't get out of it.
- **It is not a defense against a compromised host.** If someone already has your host user or root, the cage is not the thing standing between them and your machine.
- **Denial of service is up to you.** A server you deliberately run with generous CPU or memory caps can still burn them. The caps are yours to set.
- **Signing proves origin, not intent.** Publishing and pulling agents uses trust on first use: the first pull of a publisher trusts the key it sees. The sandbox, not the signature, is what contains a malicious agent.

The full security scope and reporting policy is in [SECURITY.md](SECURITY.md).

## How it works, briefly

A run is a small set of containers on private, internal-only networks. The server you cage sits alone on its own network with no route out. The only doors are small broker containers that mcpvessel runs for you: one filters every outbound network request against the allowlist you set, one brokers calls between servers, and when a server reasons with an LLM, one more holds your model key so the agent never sees it. On macOS all of this runs inside a lightweight Linux VM that mcpvessel sets up on first run, so nothing touches your host directly. On Linux it uses the host's own container runtime.

For the security scope and threat model, see [SECURITY.md](SECURITY.md). A deeper architecture writeup is on the way.

## Install

**Homebrew (recommended).** Installs a signed cask and wires up shell completions:

```sh
brew install --cask okedeji/tap/mcpvessel
```

**Direct download.** Grab the archive for your OS and architecture from the [releases page](https://github.com/okedeji/mcpvessel/releases), verify it against `checksums.txt`, then put the binary on your `PATH`. This is the right path on Windows (run it inside WSL2).

**From source.** For contributors and anyone who wants to build it themselves:

```sh
git clone https://github.com/okedeji/mcpvessel
cd mcpvessel
make build
```

Note: on macOS the release archives bundle the Linux VM image the runtime needs, so prefer Homebrew or the direct download over `go install`.

## Requirements

- macOS (Apple Silicon or Intel) or Linux. On Windows, it runs inside WSL2.
- Homebrew, for the recommended install above.
- On first run, `mcpvessel init` sets up the runtime. On macOS that is a one-time step: it downloads a small Linux VM image and starts a rootless container daemon, which takes two to five minutes depending on your connection. Every run after that is a few seconds. On Linux this is a no-op and uses the host's container runtime directly.

## Uninstall

Stop the runtime, remove the binary, then delete the state directory (this removes the macOS VM, cached images, your signing key, and config):

```sh
mcpvessel daemon stop
brew uninstall --cask mcpvessel   # or delete the binary you installed
rm -rf ~/.mcpvessel
```

## Commands

Reference for the full command surface. You only need `import` and `serve` to get started; the rest is there when you grow into it.

| Command | What it does |
| --- | --- |
| `init` | Prepare the runtime (one-time setup) |
| `import` | Wrap existing MCP servers as a caged agent |
| `serve` | Serve a caged agent to MCP clients over HTTP |
| `run` | Run an agent by routing a prompt to its main tool |
| `call` | Call a specific tool on an agent by name |
| `build` | Build an agent bundle from a Vesselfile |
| `push` / `pull` | Push or pull an agent bundle to or from an OCI registry |
| `search` / `register` | Find agents on, or publish to, the MCP Registry |
| `inspect` / `tree` | Show an agent's manifest, tools, and its `USES` tree |
| `ps` / `logs` / `stop` | List, inspect, and stop running agents |
| `spend` / `budget` | Show and manage a running agent's LLM spend |
| `trace` / `replay` / `stats` | Inspect a run: trace, record for replay, live resource usage |
| `config` / `secrets` / `trust` | Configure endpoints and caps, store secrets, pin publisher keys |

Run `mcpvessel <command> --help` for details on any of these.

## Contributing and support

- Bugs and feature requests: [open an issue](https://github.com/okedeji/mcpvessel/issues).
- Contributing: see [CONTRIBUTING.md](CONTRIBUTING.md).
- Found a security issue? Please report it privately. See [SECURITY.md](SECURITY.md).

This is a solo-maintained project, so please allow a few days for a reply.

## License

Apache 2.0. See [LICENSE](LICENSE).
