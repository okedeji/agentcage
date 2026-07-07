# The reasoner harness

`reasoner.py` is the reference brain `import --reasoning` writes into a generated
reasoning agent. It is one MCP tool, `respond(messages)`, that answers a request
by running an LLM tool-use loop over whatever tools it reaches through its `USES`
sub-agents. It ships as source, not a base image: the generated agent builds on a
stock Python image, so the file lands in the operator's directory to read and
edit, and `--reasoner <path>` swaps in a different one.

Nothing in it is agentcage-specific beyond the environment contract below. A
reasoner in any language is a drop-in replacement as long as it honors that
contract, which is the whole interface the runtime relies on.

## The environment contract

**Entrypoint.** Serve one MCP tool named after the agent's `MAIN` (`respond`
here) taking `messages` (a list of chat messages). `agentcage run <agent>
"<prompt>"` calls it with the prompt as the single user message.

**Serving.** Speak MCP over stdio when run as a root. When `AGENTCAGE_SERVE_HTTP`
is set (a `host:port`), serve streamable HTTP at `/mcp` on that address instead;
that is how the gateway reaches the agent as a sub-agent. Boot cleanly with no
`USES` tools attached, so build-time introspection can list the tool without any
sub-agents running.

**Tools.** Each `USES` edge is injected as `AGENTCAGE_USES_<ALIAS>_URL`, the
streamable-HTTP URL of that tool server behind the gateway. Connect each, list
its tools, and dispatch calls back to it. The `<ALIAS>` disambiguates when two
sub-agents expose a tool of the same name.

**LLM.** `AGENTCAGE_LLM_URL` is an OpenAI-compatible endpoint. Send a placeholder
`model` and any api key; the LLM gateway holds the real provider key, rewrites
the `model` field to the operator's configured default, meters spend against the
run's budget, and forwards `tools`/`tool_choice` untouched, so native
function-calling works. A reasoner never sees or needs a provider key.

**Operator knobs.** Read configuration from non-`AGENTCAGE_`-prefixed names; the
Agentfile parser reserves that prefix for the runtime's own injected variables.
This harness uses `REASONER_SYSTEM_PROMPT` and `REASONER_MAX_TURNS`.

## One rule that is not optional

If any `USES` tool server the agent declares cannot be reached, refuse the run
rather than answer over a partial toolset and let the model claim it used a tool
it never received. Fail closed on the whole run, not just when every server is
down: a declared capability that dropped out is a failure, not something to paper
over. A toolless run is only legitimate when the agent declares no `USES` at all.
