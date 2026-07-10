# agentcage

**Run any MCP server in a sandbox. No leaked keys, no network by default, no Docker.**

[![CI](https://github.com/okedeji/agentcage/actions/workflows/ci.yml/badge.svg)](https://github.com/okedeji/agentcage/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/okedeji/agentcage?include_prereleases&sort=semver)](https://github.com/okedeji/agentcage/releases)
[![Go](https://img.shields.io/github/go-mod/go-version/okedeji/agentcage)](go.mod)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)
![Platform](https://img.shields.io/badge/platform-macOS%20%7C%20Linux%20%7C%20WSL2-lightgrey)

<!-- DEMO GIF GOES HERE: docs/demo.gif -- the 30-second "malicious server tries to steal keys, gets blocked" recording -->

Every MCP server you `npx` runs with full access to your machine. Your files, your keys, your network, all of it. Most of them are fine. The trouble is you can't tell the fine ones apart from the one that quietly BCCs every email you send to someone else's inbox. That one is real, by the way. It was an npm package called `postmark-mcp`, it looked legitimate for fifteen versions, and then it wasn't.

agentcage runs those servers in a cage instead. One command, and no Docker to install.

> **Status: pre-1.0** (`v0.1.0-rc.x`). It works, but the CLI surface may still change between releases. Pin a release if you need something stable. See [supported versions](SECURITY.md#supported-versions).

## Contents

- [Quickstart](#quickstart)
- [What the cage actually does](#what-the-cage-actually-does)
- [What it does not protect against](#what-it-does-not-protect-against)
- [It grows past plain tool servers, when you want it to](#it-grows-past-plain-tool-servers-when-you-want-it-to)
- [How it works, briefly](#how-it-works-briefly)
- [Install](#install)
- [Requirements](#requirements)
- [Uninstall](#uninstall)
- [Commands](#commands)
- [Contributing and support](#contributing-and-support)
- [License](#license)

## Quickstart

On macOS or Linux:

```sh
brew install --cask okedeji/tap/agentcage
agentcage init
```

Now take a server you don't fully trust, put it in a cage, and hand it to your editor:

```sh
agentcage import npm:@modelcontextprotocol/server-everything
agentcage serve --listen 127.0.0.1:7000 ./server-everything
```

That prints a URL. Point Cursor, Claude, or any MCP client at it:

```
http://127.0.0.1:7000/mcp
```

Same tools you had before. Same editor. The difference is the server now runs with no access to your disk, no network it didn't ask for, and none of your API keys.

Swap that `npm:` for whatever actually makes you nervous. It takes any MCP server on npm, PyPI, or as a container image, whether or not it's in a registry: the GitHub server, a filesystem server, that one someone in a Discord swore was safe.

## What the cage actually does

Three things, and they are the whole point.

**No network unless you allow it.** A caged server starts with the internet switched off. If it genuinely needs to reach `api.github.com`, you say so, and that becomes the only place it can go. It can't phone home, and it can't ship your data anywhere you didn't approve.

**Your keys can't leak out.** A server that needs a credential to do its job, a GitHub token or a database password, gets only the ones it declared, and nothing else. It can use that key to reach the one API you allowed, but it can't send the key, or your data, anywhere else. Reaching an unknown server is off by default, and it stays off until you deliberately turn it on.

**Each server is on its own.** Caged servers can't see each other, and they can't see your host. One bad server can't reach the good ones sitting next to it.

To be clear about what this is: agentcage contains what a server can *do*. It doesn't read the server's code or vet the package for you. That is the point, though. You don't have to trust the code if it can't reach your files, your network, or your keys anyway.

## What it does not protect against

Being honest about the edges, because a security tool that overpromises is worse than one that doesn't:

- **It does not vet code.** It contains what a server can reach, not what its code says. A caged server is free to misbehave inside its cage; it just can't get out of it.
- **It is not a defense against a compromised host.** If someone already has your host user or root, the cage is not the thing standing between them and your machine.
- **Denial of service is up to you.** A server you deliberately run with generous CPU or memory caps can still burn them. The caps are yours to set.
- **Signing proves origin, not intent.** Publishing and pulling agents uses trust on first use: the first pull of a publisher trusts the key it sees. The sandbox, not the signature, is what contains a malicious agent.

The full security scope and reporting policy is in [SECURITY.md](SECURITY.md).

## It grows past plain tool servers, when you want it to

Caging a plain tool server is step one, and honestly that is most of what people need. But the same `import` takes a `--reasoning` flag that turns a pile of tool servers into an actual agent that reasons across all of them, with a spend budget attached. And a caged agent can be pushed to any container registry and pulled by a teammate, the way you push a Docker image.

That is all there when you want it. You don't need any of it to get value on day one.

## How it works, briefly

A run is a small set of containers on private, internal-only networks. The server you cage sits alone on its own network with no route out. The only doors are small broker containers that agentcage runs for you: one filters every outbound network request against the allowlist you set, one brokers calls between servers, and when a server reasons with an LLM, one more holds your model key so the agent never sees it. On macOS all of this runs inside a lightweight Linux VM that agentcage sets up on first run, so nothing touches your host directly. On Linux it uses the host's own container runtime.

For the security scope and threat model, see [SECURITY.md](SECURITY.md). A deeper architecture writeup is on the way.

## Install

**Homebrew (recommended).** Installs a signed cask and wires up shell completions:

```sh
brew install --cask okedeji/tap/agentcage
```

**Direct download.** Grab the archive for your OS and architecture from the [releases page](https://github.com/okedeji/agentcage/releases), verify it against `checksums.txt`, then put the binary on your `PATH`. This is the right path on Windows (run it inside WSL2).

**From source.** For contributors and anyone who wants to build it themselves:

```sh
git clone https://github.com/okedeji/agentcage
cd agentcage
make build
```

Note: on macOS the release archives bundle the Linux VM image the runtime needs, so prefer Homebrew or the direct download over `go install`.

## Requirements

- macOS (Apple Silicon or Intel) or Linux. On Windows, it runs inside WSL2.
- Homebrew, for the recommended install above.
- On first run, `agentcage init` sets up the runtime. On macOS that is a one-time step: it downloads a small Linux VM image and starts a rootless container daemon, which takes two to five minutes depending on your connection. Every run after that is a few seconds. On Linux this is a no-op and uses the host's container runtime directly.

## Uninstall

Stop the runtime, remove the binary, then delete the state directory (this removes the macOS VM, cached images, your signing key, and config):

```sh
agentcage daemon stop
brew uninstall --cask agentcage   # or delete the binary you installed
rm -rf ~/.agentcage
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
| `build` | Build an agent bundle from an Agentfile |
| `push` / `pull` | Push or pull an agent bundle to or from an OCI registry |
| `search` / `register` | Find agents on, or publish to, the MCP Registry |
| `inspect` / `tree` | Show an agent's manifest, tools, and its `USES` tree |
| `ps` / `logs` / `stop` | List, inspect, and stop running agents |
| `spend` / `budget` | Show and manage a running agent's LLM spend |
| `trace` / `replay` / `stats` | Inspect a run: trace, record for replay, live resource usage |
| `config` / `secrets` / `trust` | Configure endpoints and caps, store secrets, pin publisher keys |

Run `agentcage <command> --help` for details on any of these.

## Contributing and support

- Bugs and feature requests: [open an issue](https://github.com/okedeji/agentcage/issues).
- Contributing: see [CONTRIBUTING.md](CONTRIBUTING.md).
- Found a security issue? Please report it privately. See [SECURITY.md](SECURITY.md).

This is a solo-maintained project, so please allow a few days for a reply.

## License

Apache 2.0. See [LICENSE](LICENSE).
