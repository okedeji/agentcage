// done — sentinel tool. The dispatcher recognizes this name and
// exits the agentic loop. The reason argument is logged for audit.

import { DiscoveryTool } from './types';

interface Args {
  reason: string;
}

async function run(rawArgs: Record<string, unknown>): Promise<string> {
  const args = rawArgs as unknown as Args;
  return `Discovery complete: ${args.reason ?? '(no reason given)'}`;
}

export const done: DiscoveryTool = {
  name: 'done',
  description: 'Signal that discovery is complete. Call this when you have surfaced the interesting endpoints, when the target has no more discoverable surface, or when continuing further would not yield meaningfully new findings.',
  parameters: {
    type: 'object',
    properties: {
      reason: { type: 'string', description: 'One sentence summarizing why discovery is done' },
    },
    required: ['reason'],
  },
  run,
};
