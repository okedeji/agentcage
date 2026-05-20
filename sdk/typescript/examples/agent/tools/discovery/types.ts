// Discovery agent tool contract. Each tool's `run` takes LLM-emitted
// args (validated against the JSON schema declared in `parameters`)
// and returns a string the LLM sees on the next turn. The string is
// the tool's "result" in the chat history.
//
// Two control tools are special: `submit_finding` files a Discovery
// finding via the SDK; `done` is a sentinel the dispatcher checks
// for to stop the agentic loop.

export interface DiscoveryTool {
  name: string;
  description: string;
  parameters: object;
  run: (args: Record<string, unknown>) => Promise<string>;
}
