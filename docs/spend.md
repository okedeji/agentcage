# spend

Show what a running reasoning agent has spent on LLM calls so far. `spend` reads the live run's LLM gateway and prints the cumulative total, the budget it is charging against, and a per-agent breakdown of who spent what. It answers only while the run is up, since the number lives in the running gateway, not on disk.

```
mcpvessel spend RUN [-w]
```

## The RUN argument

`spend` takes exactly one argument, the run id. It is the id `mcpvessel ps` lists for a running agent, a long hex string like `researcher-7a1c4f2e9d3b`. Pass anything else and the daemon has no such run to read.

The command talks to the daemon over its control socket. It does not start the daemon: if the daemon is not running, the read fails with the raw dial error (`contacting the daemon: ...`) rather than a hint to start it, unlike `run` or `call`. Start it with `mcpvessel init` first.

## What it reads, and when it works

The spend number is not stored anywhere durable. The LLM gateway that fronts a reasoning agent logs a cumulative spend snapshot after every metered call, and `spend` reads the last such snapshot off that gateway's live logs. Three things follow from that:

- **Only reasoning runs have a gateway.** A plain tool collection or a non-reasoning agent never routes LLM calls through a gateway, so it has no spend to report. Asking for its spend is a 404.
- **Only a running gateway can be read.** Once the run stops, its gateway is gone and the read fails. A finished run's total cost is captured by the runtime at teardown and shown in `mcpvessel ps`; `spend` is for a run that is still up.
- **The first metered call has to have happened.** The snapshot is written after a call, so a reasoning run that is up but has not yet made its first billable LLM call has no snapshot to read yet. It reports the same 404 as a run that does not reason at all.

When any of these is the case the daemon returns `no live spend for run <id> (spend reads a live reasoning run; a finished run's total is in 'mcpvessel ps')`.

## The readout

Without `-w`, `spend` prints one snapshot and exits. The first line is the total; the lines under it are the per-agent breakdown, sorted by agent name so the order is stable across refreshes.

```
LLM spend: $0.0225 of $1.00 budget
  a             $0.015   (2 calls)
  b             $0.0075  (1 call)
```

The total line has two forms. With a budget set it reads `LLM spend: $<total> of $<budget> budget`. With no budget (an unbounded run) it reads `LLM spend: $<total> (no budget set)`. A zero budget is treated as no budget, which is how an unbounded run is expressed internally.

Each agent line is the agent's key, its own spend, and its call count. The call count is pluralized (`1 call`, `2 calls`).

## Per-agent slices of one shared budget

A reasoning agent that composes sub-agents runs them all against a single shared budget for the whole run tree, not a budget per agent. The total line is the tree's combined spend against that one budget; the per-agent lines slice that same total, showing which agent burned which part of it. The slices sum to the total. The budget on the total line is the one cap they all draw down together, so when the tree reaches it every agent's next call is refused, whichever agent it belongs to.

## Micro-USD amounts

Costs are metered internally in micro-USD (millionths of a dollar), so a single cheap call registers instead of rounding to zero. `spend` renders each amount as dollars, keeping at least two decimals and as many more as the value needs, trimming trailing zeros past the second. So `$1.00` prints as `1.00`, and a sub-cent figure like 22,500 micro-USD prints as `0.0225` rather than collapsing to `0.02`. This is the same rendering `ps`, `trace`, and `inspect` use for money, so amounts line up across commands.

## Watch mode

**`-w` / `--watch`** refreshes the total in place instead of printing once and exiting. It re-reads the gateway every two seconds and rewrites the total line over itself (a carriage return, no scroll). Watch mode shows only the total line; it does not print the per-agent breakdown. Run `spend` without `-w` when you want the breakdown.

Watch mode exits cleanly, never with an error, in two cases:

- **The run ends.** When a read fails mid-loop, `spend` treats it as the run going away rather than a fault: it prints a newline to close the in-place line and exits 0. So `spend -w` is a natural way to watch a run's cost until it finishes on its own.
- **You interrupt it.** Ctrl-C ends the loop, prints a newline, and exits 0.

Because any read failure ends the loop quietly, `spend -w` with a run id that never had spend (a wrong id, a non-reasoning run, a run already stopped) prints just a blank line and exits 0 with no message. Drop `-w` to see the daemon's 404 explaining why.

## Flags

| Flag | Meaning |
| --- | --- |
| `-w`, `--watch` | Refresh the total line in place every 2 seconds until the run ends or you interrupt it. Shows the total only, not the per-agent breakdown. Exits 0 on both, and on any read failure. |

## Examples

```sh
# One snapshot: total, budget, and the per-agent breakdown.
mcpvessel spend researcher-7a1c4f2e9d3b

# Watch the total climb in place until the run finishes.
mcpvessel spend -w researcher-7a1c4f2e9d3b

# Find the run id first, then read its spend.
mcpvessel ps
mcpvessel spend researcher-7a1c4f2e9d3b
```

## Notes

- The number is a snapshot taken after the most recent metered call. Between calls it does not move, and it can lag the true spend of an in-flight call until that call returns and is billed.
- The read is best-effort off the gateway's logs. If the gateway is momentarily unreadable the command reports no spend rather than a partial figure.
- `spend` only reads. To change a running agent's cap without restarting it, use `mcpvessel budget set`. To watch the cap enforce, a run that reaches its budget refuses its next LLM call.
- The per-agent keys are the real agent keys, kept for the tally, not the capability tokens the gateway injects into each agent's URL, so a sibling cannot misattribute another agent's spend.

## See also

- [run](run.md): starts the reasoning run this reads, and sets its cap with `--budget`.
- [ps](ps.md): lists running run ids to pass here, and carries a finished run's final cost once its gateway is gone.
- [budget](budget.md): change a running agent's LLM budget mid-run; `spend` shows the budget, `budget set` moves it.
- [trace](trace.md): a finished run's per-call cost breakdown, read from the same gateway telemetry.
- README: [Give it a brain](../README.md#give-it-a-brain) for building the reasoning agent whose spend this reports.
