# Contributing

Thanks for looking. agentcage is early and solo-maintained, so the most useful
contributions right now are bug reports with a reproduction, and small focused
PRs. Before a large change, open an issue so we can agree on the shape first.

## Building and testing

```sh
make ci            # fmt-check, vet, lint, test, build (run this before build)
make build         # the host CLI -> bin/agentcage
make build-linux   # the in-VM companion binary (needed to actually run agents)
```

You need Go 1.26+. `make lint` needs
[golangci-lint](https://golangci-lint.run/welcome/install/). Running agents
needs a container runtime: containerd + buildkit + nerdctl on Linux, or the
bundled Lima VM on macOS (`agentcage init` sets it up).

The test suite is hermetic. It uses `httptest` servers and fakes rather than a
real daemon or VM, so `make test` passes offline with no containers running.
Keep it that way: a test that needs a live runtime does not belong in the unit
suite.

## Pull requests

- Run `make ci` before opening a PR; a red pipeline will not merge.
- Keep the change focused. One concern per PR.
- Match the surrounding code. Look at a neighboring file before inventing a
  pattern.
- Add or update tests for behavior you change.

## House style

A few conventions the codebase holds to. New code should match:

- **Comments say what the code cannot.** A comment earns its place by stating a
  constraint, invariant, or trade-off, not by narrating the next line. Density
  follows subtlety: gnarly code gets an explanation, obvious code gets nothing.
- **No em-dashes or en-dashes** in comments, help text, or docs. Use a period,
  comma, colon, or parenthetical.
- **Fail closed.** A missing input, an unparseable config, a policy that cannot
  be evaluated: refuse, do not guess. This is a security tool.
- **Money is integer micro-USD.** No floats for currency, anywhere.
- **Secrets come from stdin or the store, never argv**, so they stay out of the
  process table and shell history.
- User-facing errors are lowercase, specific, and name the remedy.

## Reporting security issues

Not here. See [SECURITY.md](SECURITY.md) for private disclosure.
