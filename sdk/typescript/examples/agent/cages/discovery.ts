// Discovery cage: agentic loop.
//
// Registers 6 tools with the LLM (fetch_path, crawl, dir_fuzz,
// recon_scan, submit_finding, done). The LLM picks one tool per turn,
// sees the result, picks the next. Capped at MAX_ITERATIONS to bound
// cost. Stops early when the LLM calls `done`.
//
// Pattern contrast with the exploitation cage: exploitation is a
// single-shot decision (pick one tool, run it, done). Discovery is
// an iterative loop because surface mapping is many small decisions
// — what to fetch next depends on what was just seen.

import { env } from '../lib/env';
import { callLLMWithTools, LLMMessage } from '../lib/llm';
import { DiscoveryTool } from '../tools/discovery/types';
import { fetchPath } from '../tools/discovery/fetch-path';
import { crawl } from '../tools/discovery/crawl';
import { probePaths } from '../tools/discovery/probe-paths';
import { dirFuzz } from '../tools/discovery/dir-fuzz';
import { reconScan } from '../tools/discovery/recon-scan';
import { submitFinding } from '../tools/discovery/submit-finding';
import { done } from '../tools/discovery/done';

const TOOLS: DiscoveryTool[] = [fetchPath, crawl, probePaths, dirFuzz, reconScan, submitFinding, done];
const TOOLS_BY_NAME = new Map(TOOLS.map((t) => [t.name, t]));

const MAX_ITERATIONS = 25;

const SYSTEM_PROMPT = `You are a penetration testing agent performing attack surface discovery.

Your goal: map the target's surface and submit Discovery findings for endpoints worth exploitation testing. The coordinator will read your findings to plan exploitation cages, so call out paths that look meaningfully exploitable (admin panels, auth endpoints, API routes, file uploads, exposed configs).

Strategy guidelines:
- Start with recon_scan on / to identify the tech stack and surface obvious exposures.
- Use fetch_path to look at one specific endpoint in detail when you need its body/headers.
- Use crawl when the target looks like a SPA or has heavy JavaScript (renders routes client-side).
- Use probe_paths to check candidate paths YOU generated from prior context — the tech stack you identified, references seen in HTML/JS bundles, conventions of the framework you detected (e.g. Next.js → /_next/data, Rails → /rails/info/routes, Spring → /actuator/*). This is your primary discovery tool once you have any context.
- Use dir_fuzz only as a last resort when you have no context to generate candidates — blind brute-force with a generic wordlist. Prefer probe_paths if you can guess intelligently.
- Submit findings as you discover them — do not hoard until the end. The coordinator works with findings as they arrive.
- Call done when you have a reasonable map of the surface. Better to stop slightly early than to burn iterations on diminishing returns.

You are bounded: maximum ${MAX_ITERATIONS} tool calls. Pace yourself.`;

export async function runDiscovery(): Promise<void> {
  console.log(`\n── Discovery: target=${env.target} ──`);
  if (env.scopePaths.length > 0) {
    console.log(`Operator-supplied paths: ${env.scopePaths.join(', ')}`);
  }

  const history: LLMMessage[] = [
    { role: 'system', content: SYSTEM_PROMPT },
    {
      role: 'user',
      content: buildInitialPrompt(),
    },
  ];

  const visited = new Set<string>();
  let submittedCount = 0;
  let stopped = false;

  for (let iter = 1; iter <= MAX_ITERATIONS && !stopped; iter++) {
    const { toolCall, assistantMessage, message } = await callLLMWithTools(history, TOOLS, {
      toolChoice: 'required',
    });
    history.push(assistantMessage);

    if (!toolCall) {
      console.log(`Iteration ${iter}: LLM produced no tool call (msg: ${message.slice(0, 200)}). Stopping.`);
      break;
    }

    const tool = TOOLS_BY_NAME.get(toolCall.name);
    if (!tool) {
      const errMsg = `Unknown tool: ${toolCall.name}. Registered tools: ${TOOLS.map((t) => t.name).join(', ')}`;
      console.log(`Iteration ${iter}: ${errMsg}`);
      history.push({ role: 'tool', tool_call_id: toolCall.id, content: errMsg });
      continue;
    }

    console.log(`Iter ${iter}/${MAX_ITERATIONS}: ${toolCall.name}(${JSON.stringify(toolCall.arguments).slice(0, 120)})`);

    const result = await tool.run(toolCall.arguments);
    history.push({ role: 'tool', tool_call_id: toolCall.id, content: result });

    if (toolCall.name === 'fetch_path' || toolCall.name === 'crawl' || toolCall.name === 'dir_fuzz' || toolCall.name === 'recon_scan') {
      const probedPath = (toolCall.arguments.path ?? toolCall.arguments.seed_path ?? toolCall.arguments.base_path) as string;
      if (probedPath) visited.add(probedPath);
    } else if (toolCall.name === 'probe_paths') {
      const probedPaths = (toolCall.arguments.paths ?? []) as string[];
      for (const p of probedPaths) visited.add(p);
    }
    if (toolCall.name === 'submit_finding') submittedCount++;
    if (toolCall.name === 'done') stopped = true;
  }

  if (!stopped) {
    console.log(`Discovery hit iteration cap (${MAX_ITERATIONS}) without 'done'. Submitted ${submittedCount} findings.`);
  } else {
    console.log(`\nDiscovery complete. Submitted ${submittedCount} findings across ${visited.size} probes.`);
  }
}

function buildInitialPrompt(): string {
  const parts: string[] = [];
  parts.push(`Target: https://${env.target}`);
  if (env.objective) parts.push(`Objective: ${env.objective}`);
  if (env.scopePaths.length > 0) {
    parts.push(`Operator-supplied paths in scope (start here):\n${env.scopePaths.map((p) => `  ${p}`).join('\n')}`);
  } else {
    parts.push(`No operator-supplied paths. Start with recon_scan on / to characterize the target.`);
  }
  parts.push(`\nBegin discovery. Pick your first tool call.`);
  return parts.join('\n');
}
