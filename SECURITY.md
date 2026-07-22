# Security policy

mcpvessel runs agents in isolated containers behind policy gateways, with a
signing and trust model over the artifacts. A hole in the sandbox or the trust
model is the most serious kind of bug it can have. Reports are welcome and taken
seriously.

## Reporting a vulnerability

Please report privately, not in a public issue:

- Open a [GitHub private security advisory](https://github.com/okedeji/mcpvessel/security/advisories/new), or
- Email **tobiokedeji@gmail.com** with `mcpvessel security` in the subject.

Include what you need to reproduce it: the Vesselfile or bundle, the commands,
and what you expected versus what happened. A proof of concept helps but is not
required.

This is a solo-maintained project, so please allow a few days for an initial
reply. Once a fix is out, credit is given in the release notes unless you would
rather stay anonymous.

## Scope

In scope, most valuable first:

- Sandbox escape: an agent reaching the host, another cage, or the network it
  was not granted.
- Gateway bypass: reaching a denied or banned tool, or a sub-agent a `BAN`
  should have blocked.
- LLM key or secret exposure to an agent, or spend that escapes the budget.
- Signature or trust bypass: a bundle verifying under the wrong key, or a
  key-mismatch that does not fail closed.
- Egress bypass: reaching a host outside an `EGRESS allow:` list, or SSRF
  through the egress proxy.

Out of scope:

- The known limits of signing: the first pull of a publisher trusts the key it
  sees (trust on first use), and signing proves origin, not intent. The sandbox,
  not the signature, is what contains a malicious agent.
- Denial of service from an agent you deliberately ran with generous caps.
- Anything requiring you to already hold the host user's credentials or root.

## Signing and trust

Every bundle is signed on push and verified on pull. The first pull of a
publisher pins the key it sees and prints its fingerprint; every later pull must
match that pin. A changed key fails closed with a loud error rather than swapping
silently. This is trust on first use, the same model as SSH known hosts.

Servers published from this project are signed with key fingerprint
`dbb184de32d2` (scope `ghcr.io/okedeji`). Your first pull prints
`Signature verified; pinned signing key dbb184de32d2 ... (first use)`. Confirm it
matches this before you trust it. If a later pull reports a key mismatch and you
have not been told to expect a rotation, stop and check.

The key was rotated from `bf4894a180f2` on 2026-07-22, alongside the move to
the tag-bound signature format. If you pinned the old key, the mismatch you see
is this rotation: run `mcpvessel trust rm ghcr.io/okedeji`, pull again, and
confirm the new fingerprint above.

The limits are the ones listed above: a signature proves origin, not intent, and
the sandbox, not the signature, is what contains a malicious agent.
