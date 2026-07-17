# trace

Show what a finished run actually did with a model. `trace` renders one run's trace as a tree: the run at the root, each reasoning agent under it, and every LLM call that agent made with its model, token counts, cost, and wall-clock duration. It reads a trace the daemon already recorded when the run finished, so it is a read of history, not a fresh run. A run that never called a model has no trace.

```
mcpvessel trace RUN
```

`trace` takes exactly one argument and no flags. It talks to the daemon over its socket and prints the stored tree to stdout.

## The RUN argument

`RUN` is a run id, the value in the first column of `mcpvessel ps`. `ps` lists both live runs and finished ones from history, so the id you pass here is usually one you copied from a finished row. The id is assigned when the run starts (for example `researcher-7a1c4f2e9d3b`) and stays stable for the life of that run's history record.

There is one id per run. Serving an agent and prompting it many times is still separate runs with separate ids and separate traces. Pass the exact id, `trace` does no prefix matching or fuzzy resolution.

## What a trace shows

The tree has three kinds of node, printed by depth with two spaces of indent per level.

**The run** is the root, named `mcpvessel.run`. Its width is the run's whole wall time, from when the daemon started it to when it ended.

**An agent** is a node named `agent:<name>`, one per reasoning cage that made at least one LLM call. The name is the agent's key in the composed graph (the root agent, and any sub-agent that itself reasoned). An agent node's start and end are widened to span its own calls: it begins at its first call and ends at its last, so its duration is the window its calls covered, not idle time around them.

**An LLM call** is a leaf named `mcpvessel.llm.call`, one per metered call the agent made to a provider. This is where the model, tokens, and cost live.

Alongside agents, the run root can also hold **sub-agent call** nodes named `mcpvessel.sub_agent.run`, one per parent-to-sub-agent `tools/call`. These mark where the reasoning agent invoked another caged agent as a tool. They carry the call's edge and tool internally but render as just a name and a duration, so they show you when and how long a sub-agent was called without repeating the callee's own LLM calls.

The root's children (agent nodes and sub-agent call nodes) are sorted by start time, so reading top to bottom follows the run's timeline.

## How to read a row

Each line is `name`, then the span's duration (rounded to the millisecond, omitted when zero), then, for an LLM call, its attributes:

```
mcpvessel.run  4.281s
  agent:root  4.102s
    mcpvessel.llm.call  1.284s  anthropic/claude-sonnet-4-5  1180->342 tok  $0.0121
    mcpvessel.llm.call  1.077s  anthropic/claude-sonnet-4-5  1502->210 tok  $0.0098
  mcpvessel.sub_agent.run  0.643s
```

The attributes on an LLM call line are:

- **model**: the `provider/model` the gateway routed the call to. This can differ from the model the Vesselfile named if a provider fallback rewrote it.
- **`in->out tok`**: prompt tokens into the model, completion tokens out. Printed only when the call reported token counts.
- **cost**: the call's price in dollars, shown only when it is above zero. Sub-cent amounts keep their precision (trailing zeros past two decimals are trimmed), so a fraction of a cent still reads as a real number rather than `$0.00`.

Structural nodes (the run, an agent, a sub-agent call) have no attribute tail, only a name and a duration. Durations use the gateway's own clock for exact spans; that clock is not perfectly aligned with the daemon's wall clock, so per-call durations are trustworthy even when their absolute placement inside the run window is approximate.

## Where the trace comes from

You do not record a trace on purpose. The daemon builds one automatically as every run finishes. When a run ends it reads the LLM call events and sub-agent call events off the gateway, groups the calls by agent into the tree above, serializes it to JSON, and stores it on the run's history record. `trace` just fetches that stored JSON and prints it.

Two conditions gate whether a trace exists:

- **The run made at least one LLM call (or one sub-agent call).** A tool collection, or a reasoning run that answered without ever hitting a model, produces no trace. There is nothing to draw.
- **Run history is on.** The daemon keeps history in a store it opens at startup. If that store fails to open, the daemon runs without history and no traces are kept. History is on by default.

Because the trace rides on the history record, it lives exactly as long as that record does. Purge or lose the record and its trace goes with it.

## Errors

`trace` surfaces one error for every failure, with a hint appended: `(is the daemon running? does the run exist and did it make any LLM calls?)`. The cases behind it:

- **The daemon is not reachable.** No socket, or nothing listening. Start it with `mcpvessel daemon` (or let `mcpvessel init` bring it up).
- **The run is unknown.** No history record with that id.
- **The run has no trace.** The record exists but the run made no LLM call, or history was off when it ran.
- **History is unavailable.** The daemon came up without a history store.

All four come back through the same message, so the hint lists the likely causes rather than the daemon distinguishing them for you on the command line.

## Flags

`trace` has no flags of its own and inherits none. Its only input is the `RUN` argument, which is required (exactly one).

## Examples

```sh
# Trace a finished run by the id ps showed you.
mcpvessel trace researcher-7a1c4f2e9d3b

# Find the run first, then trace it.
mcpvessel ps
mcpvessel trace oncall-3f9b2c7a1e5d
```

## Notes

- The trace is a summary, not a transcript. It shows model, tokens, cost, and timing, never the prompts or the model's replies. To keep a run's full request and response bodies, run it under `mcpvessel replay record`, which writes a `.replay` artifact you can keep, share on a bug report, or analyze. Trace is automatic and lightweight; a replay recording is opt-in per run and heavier.
- A sub-agent call node shows that a sub-agent was invoked and for how long, but not what the sub-agent did with a model. Each caged reasoning agent meters through its own gateway, so a sub-agent's own LLM calls belong to its own run and trace, not the parent's.
- The tree's shape comes from grouping calls by agent, not from the gateway reporting a full call graph. Two calls the same agent made land under that one agent node in start-time order; the tree does not reconstruct which call triggered which tool use.
- An empty trace (a root with no children) prints nothing at all. If `trace` returns cleanly with no output, the run finished with a trace record but no agent or sub-agent activity to draw.

## See also

- [run](run.md): boot an agent and get a trace recorded for it automatically when it finishes.
- [serve](serve.md): keep an agent up; each prompt is its own run with its own id and trace.
- [daemon](daemon.md): the process that records run history and serves the trace, and where that history lives.
- [inspect](inspect.md): read a bundle's tools and metadata before you run it, the static counterpart to this run-time view.
- README: [Give it a brain](../README.md#give-it-a-brain) for building the reasoning agents whose runs produce traces.
