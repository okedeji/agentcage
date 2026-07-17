# budget

Change a running agent's LLM budget without restarting it. A reasoning run enforces a spend cap: once its LLM cost reaches the cap, the next model call is refused. `budget` sets that cap live, on a run already in flight. Raise it to let a run that hit its cap keep going. Lower it to stop a run at the next call. The number takes effect immediately, no reboot, and no re-issuing of the prompt.

```
mcpvessel budget set RUN AMOUNT
```

`budget` is a parent with a single subcommand, `set`. Running `mcpvessel budget` on its own just prints help.

## budget set

`set` takes two positional arguments and nothing else. `RUN` is the run id from `mcpvessel ps`. `AMOUNT` is a USD figure like `5.00`. It resolves the amount to micro-USD, opens the daemon socket, and posts the new cap to the run. On success it prints `budget for <RUN> set to $<AMOUNT>`, echoing the amount exactly as you typed it.

There are no flags. Everything the command needs is in the two arguments.

## How the change reaches the run

A budget change travels a deliberately narrow path, because the whole point of a cap is that the caged agent cannot lift its own.

1. The CLI parses `AMOUNT` to integer micro-USD and posts `POST /runs/<id>/budget` to the local daemon over its Unix socket.
2. The daemon confirms it is holding a run by that id (a 404 otherwise), then reaches the run's LLM gateway. The gateway runs in its own container, named `<run>-llm`, with two listeners: an agent-facing one the cages talk to, and a control listener bound to container loopback that nothing on the run network can reach.
3. The daemon does not open a socket to that control listener. It `exec`s a small client (`mcpvessel llm-control budget`) inside the gateway container. Running there, the client is the only thing that can post to the loopback control port. The exec is the authorization: only the host daemon can exec into the container, so only the operator can move the budget.
4. The gateway's control handler rejects a negative number, then writes the new cap into its meter under a lock.

Because the control listener carries no route the agents can see, a cage cannot raise the budget of the gateway it talks to. The operator surface and the agent surface are separate listeners by design.

## The over-budget gate, and raising versus lowering

The gateway meters every model call: it adds each call's cost to a running total for the whole run (the budget is shared across the agent tree, not per sub-agent). Before it forwards a call, it checks the gate.

The gate is a soft cap read live. On each incoming call the gateway asks: is the budget positive and has the total reached it. If so, the call is refused with `402 over-budget: the run's LLM budget is spent`. If not, the call goes through and is metered on the way back. Two consequences follow, and both are what make a live change work:

- **Raising** the budget above the current spend clears the gate. A run that stalled at its cap makes its next call and continues, with no restart and no lost conversation.
- **Lowering** the budget to at or below the current spend closes the gate. The run stops at its next call. A call already in flight is not aborted; the cap is checked at the start of a call, not mid-stream.

Because metering happens after a call returns, the gate can overshoot by at most one in-flight call. The cap is a cost guardrail, not a hard kill switch. Setting a number below what a run has already spent does not claw anything back or interrupt the current call; it only forbids the next one.

Setting `AMOUNT` to `0` makes the run unbounded: a zero budget disables the gate entirely. This differs from `mcpvessel run --budget`, which rejects `0` at start (there you omit the flag to run unbounded). Live, `budget set <run> 0` is the way to remove a cap from a run that already has one.

## Which runs have a budget

Only a run that reasons has an LLM gateway, and only a gateway has a budget to set. A wrapped tool collection (a caged server with no `MAIN`) does not reason, so it has no gateway and no cap. Targeting one, or any run whose gateway is gone, fails with an error that names the likely cause: whether the run reasons, and whether it is still running.

The command also only reaches a run the daemon is holding over stdio, the kind `mcpvessel ps` lists. A serve front door is a pool, not a single held run, and is not a `budget set` target; it reports as no such run.

## Arguments

| Argument | Meaning |
| --- | --- |
| `RUN` | The run id from `mcpvessel ps`, for example `researcher-7a1c4f2e9d3b` (an agent name plus a short digest). Must name a held, reasoning run. |
| `AMOUNT` | The new cap in USD, for example `5.00` or `0.50`. Resolved to micro-USD, so at most six decimal places; a finer number is rejected. Negative is rejected. `0` makes the run unbounded. |

There are no command-specific flags.

## Examples

```sh
# A run stalled at its cap. Raise it and let it finish.
mcpvessel budget set researcher-7a1c4f2e9d3b 10.00

# Rein in a run that is spending faster than expected. It stops at the next call.
mcpvessel budget set oncall-3f9a2b1c 1.00

# Remove the cap entirely and let the run go unbounded.
mcpvessel budget set researcher-7a1c4f2e9d3b 0
```

## Notes

- A live change is checked at the start of the next call, not against the call already running. Lowering the budget never aborts an in-flight call, and the total can overshoot the cap by one call.
- The budget is shared across the run's whole agent tree. Setting it caps the sum of every sub-agent's spend, not any one agent's.
- The success line echoes the amount you typed (`set to $10.00` if you wrote `10.00`, `set to $10` if you wrote `10`). It does not re-format the number.
- Unlike `run --budget`, which forbids `0` at start, `budget set` accepts `0` to make a running cap unbounded.
- An agent inside the cage cannot change its own budget. The control listener is loopback-only and reachable solely by a host `exec` into the gateway container.
- If the command errors with a hint about the daemon, the daemon is not reachable on its socket. Start it (see [daemon](daemon.md)) and retry.

## See also

- [run](run.md): `--budget` sets the run's initial cap, and the `BUDGET` directive is the agent author's advisory default that `--budget` overrides.
- [ps and stop](daemon.md): where run ids come from, and how held runs are listed and released.
- [serve](serve.md): the long-lived front door, whose runs `budget set` does not target.
- [give it a brain](../README.md#give-it-a-brain): why a reasoning run has an LLM gateway and a spend cap in the first place.
