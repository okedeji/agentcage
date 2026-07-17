# The reasoner harness

When you add `--reasoning` to `import`, mcpvessel writes a small Python program into the generated agent and makes it the agent's `MAIN`. That program is the reasoner: the brain that takes a request, runs an LLM tool-use loop over the caged servers, and returns an answer. This page is what it does, the contract it lives by, and how to shape or replace it.

The reasoner is one MCP tool, `respond(messages)`. Everything an agent does when you `run`, `call`, or `serve` it flows through that one tool. It reaches the tools of its `USES` sub-agents through the MCP gateway, reaches a model through the LLM gateway, and holds no provider key of its own. It ships as source, not a sealed base image, so the file lands in your agent's directory as `reasoner.py`, yours to read, edit, and rebuild. If you want a different brain entirely, `import --reasoning --reasoner ./mybrain.py` swaps yours in, and any program in any language works as long as it honors the contract below.

## The loop, in one pass

A call to `respond(messages)` does this:

1. Builds the conversation: the system prompt first, then the caller's messages. `run @me/agent "question"` arrives as a single user message.
2. Opens a live MCP session to every `USES` sub-agent, lists their tools, and hands the model the union as OpenAI function schemas.
3. Runs a bounded loop. Each turn asks the model for a completion. If the model calls tools, the reasoner dispatches each call to the right sub-agent, appends the results, and loops. If the model answers with no tool call, that answer is the result.
4. Closes every sub-agent session when the call ends, win or lose.

The model does the deciding; the reasoner is the harness that keeps that deciding honest, bounded, and connected to real tools.

## The environment contract

The reasoner reads everything it needs from the environment the runtime injects. This is the whole interface, and it is what makes the reasoner replaceable: match this and your program is a drop-in brain.

**Serving.** Run as an agent root, speak MCP over stdio. When `VESSEL_SERVE_HTTP` is set to a `host:port`, serve streamable HTTP at `/mcp` on that address instead; that is how the MCP gateway reaches the agent when it is a sub-agent of another. The tool must boot cleanly with no sub-agents attached, because build-time introspection lists the `MAIN` tool with nothing else running.

**Tools.** Each `USES` edge is injected as `VESSEL_USES_<ALIAS>_URL`, the streamable-HTTP URL of that sub-agent's tool server behind the gateway. The reasoner connects to each, lists its tools, and dispatches calls back to it. The `<ALIAS>` labels the edge so that when two sub-agents expose a tool of the same name, the second is disambiguated (`alias_toolname`) rather than shadowed.

**LLM.** `VESSEL_LLM_URL` is an OpenAI-compatible endpoint. The reasoner sends a placeholder `model` field and a throwaway API key. The LLM gateway holds the real provider key, rewrites the `model` to the operator's configured default, meters the spend against the run's budget, and forwards `tools` and `tool_choice` untouched so native function-calling works. The reasoner never sees, needs, or can leak a provider key. The endpoint streams, so a long completion meters incrementally and does not risk a read timeout.

None of these are yours to set. They carry the `VESSEL_` prefix precisely because the Vesselfile parser forbids an author from declaring an `ENV` under that prefix, so a bundle cannot rewrite its own plumbing.

## The system prompt

The reasoner ships with a built-in system prompt, and it is not a placeholder. It is the tool-use discipline that keeps a model honest: use only the tools provided, never claim a tool result you did not get, ground every claim in a tool output or the user's message, do not pretend a failed tool succeeded, do not repeat a call hoping for a different answer, stop once you can answer, be concise. Every reasoning agent gets this scaffold.

Your prompt is added to it, never in place of it. Set it at build time with `import --reasoning --prompt "You are an on-call SRE; escalate P1s and cite the runbook."`, or for a real multi-line prompt, `--prompt-file ./prompt.md`. It lands in the agent's directory as a plain file the harness reads through `REASONER_SYSTEM_PROMPT_FILE`, and the harness appends it under an "Additional instructions" heading. Because the prompt is the agent's identity, it is baked into the bundle and travels with `push` and `pull`; it is not a per-run argument. Edit the file and rebuild to change it. (An inline `REASONER_SYSTEM_PROMPT` is read as a fallback when no file is set.)

## Operator knobs

The loop's bounds are environment variables with sane defaults, so you can tune a deployment without editing the file. They use plain names, not the reserved `VESSEL_` prefix.

| Variable | Default | What it bounds |
| --- | --- | --- |
| `REASONER_MAX_TURNS` | `12` | Tool-loop turns before the reasoner forces a final answer. Guards a runaway loop; the real ceiling is the run's budget. |
| `REASONER_MAX_RETRIES` | `5` | Retries the OpenAI SDK makes on a 429, 5xx, or timeout, with backoff that honors `Retry-After`. A rate-limit blip does not kill a deployed run. |
| `REASONER_LLM_TIMEOUT` | `120` | Seconds before a single completion request times out. |
| `REASONER_MAX_TOOL_CHARS` | `16000` | Character cap on one tool result. A larger result is truncated with a visible marker so one big payload cannot overflow the model's context. |
| `REASONER_MAX_TOOL_FAILURES` | `3` | Identical failing tool calls before that call is cut off, so the model cannot burn the whole budget retrying a call that will never work. |

## What makes it production-minded

The loop is deliberately defensive, because a reasoning agent runs unattended and pays real money per turn:

- **Fail closed on a missing tool server.** If any `USES` sub-agent the agent declares cannot be reached, the reasoner refuses the whole run rather than answer over a partial toolset and let the model claim a tool it never received. A toolless run is legitimate only when the agent declares no `USES` at all.
- **Malformed arguments feed back.** If the model emits tool arguments that are not valid JSON, or names a tool that does not exist, the reasoner returns that as the tool result so the model can correct itself, instead of crashing the turn.
- **A doomed call gets cut off.** The same tool failing `REASONER_MAX_TOOL_FAILURES` times with identical arguments is refused with a message telling the model to stop and answer with what it has.
- **The turn limit degrades gracefully.** Hitting `REASONER_MAX_TURNS` does not error. The reasoner makes one final tool-free pass asking the model for its best answer from what it gathered, and notes what it could not finish.
- **Streaming is opt-in and free when unused.** When a caller sets an MCP progress token (mcpvessel `serve` does this for a REST `stream:true` request), the reasoner reports answer tokens as they generate via progress notifications, which `serve` turns into SSE `delta` events. With no token, the same code returns the finished answer, so `run`, `call`, and non-streaming callers are untouched. The final tool result is always the complete answer either way.

## Writing your own

Because the contract above is the whole interface, replacing the reasoner is a supported move, not a hack. Point `import --reasoning --reasoner ./mybrain.py` at your file, or edit the generated `reasoner.py` in place and rebuild. Your program must:

- Serve one MCP tool named after the agent's `MAIN`, taking `messages`.
- Speak MCP over stdio, and serve streamable HTTP at `/mcp` on `VESSEL_SERVE_HTTP` when that is set.
- Boot with no sub-agents attached, so introspection can list the tool.
- Read its tools from `VESSEL_USES_<ALIAS>_URL` and its model from `VESSEL_LLM_URL`.
- Fail closed when a declared tool server is unreachable.

Honor that and the runtime treats your brain exactly like the reference one: it caches, ships, and cages the same way, and `run`, `call`, and `serve` drive it unchanged.

## See also

- [import](import.md): writes the reasoner with `--reasoning`, shapes it with `--prompt` / `--prompt-file`, and swaps it with `--reasoner`.
- [run](run.md), [call](call.md): drive the `respond` tool from your terminal.
- [serve](serve.md): fronts the agent on HTTP, including the SSE streaming path.
- [VESSELFILE.md](VESSELFILE.md): the `MAIN`, `MODEL`, `USES`, and `SECRETS` directives that configure a reasoning agent.
- [ARCHITECTURE.md](ARCHITECTURE.md): the LLM gateway and MCP gateway the reasoner talks to, and why it never holds a key.
