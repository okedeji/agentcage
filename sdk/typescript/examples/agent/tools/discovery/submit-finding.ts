// submit_finding — files a Discovery finding via the SDK. The agent
// calls this when it has identified an endpoint worth surfacing to
// the operator and the coordinator (e.g. an admin panel, API route,
// file upload form, exposed config).

import { FindingKind, Severity, newFindingId } from '@agentcage/sdk';
import { agent } from '../../lib/sdk';
import { env } from '../../lib/env';
import { DiscoveryTool } from './types';

interface Args {
  path: string;
  vuln_classes: string[];
  priority: 'low' | 'medium' | 'high';
  reason: string;
  technologies?: string[];
}

async function run(rawArgs: Record<string, unknown>): Promise<string> {
  const args = rawArgs as unknown as Args;
  if (typeof args.path !== 'string' || !args.path) {
    return 'ERROR: submit_finding requires a string `path`';
  }
  if (!Array.isArray(args.vuln_classes) || args.vuln_classes.length === 0) {
    return 'ERROR: submit_finding requires a non-empty `vuln_classes` array';
  }
  if (typeof args.reason !== 'string' || !args.reason) {
    return 'ERROR: submit_finding requires a `reason` string';
  }
  const priority = args.priority ?? 'medium';
  const techs = Array.isArray(args.technologies) ? args.technologies : [];

  await agent.submitFinding({
    id: newFindingId(),
    kind: FindingKind.Discovery,
    severity: Severity.Info,
    title: `Discovered: ${args.path}`,
    endpoint: `https://${env.target}${args.path}`,
    description: `${args.reason} Technologies: ${techs.join(', ') || 'unknown'}. Suggested tests: ${args.vuln_classes.join(', ')}. Priority: ${priority}.`,
    evidence: {
      metadata: {
        priority,
        vuln_classes: args.vuln_classes.join(','),
        technologies: techs.join(','),
      },
    },
  });

  return `Submitted Discovery finding for ${args.path} (priority=${priority}, vuln_classes=${args.vuln_classes.join(',')})`;
}

export const submitFinding: DiscoveryTool = {
  name: 'submit_finding',
  description: 'File a Discovery finding for an endpoint worth surfacing. The coordinator will read these to plan exploitation. Use for: admin panels, API routes, auth endpoints, file uploads, exposed configs, anything accepting user input or showing exploitable surface.',
  parameters: {
    type: 'object',
    properties: {
      path: { type: 'string', description: 'URL path of the endpoint (e.g. /admin)' },
      vuln_classes: {
        type: 'array',
        items: { type: 'string' },
        description: 'Vulnerability classes worth testing here (e.g. ["sqli", "auth_bypass"]).',
      },
      priority: {
        type: 'string',
        enum: ['low', 'medium', 'high'],
        description: 'How urgent this surface looks. high = obviously exploitable; low = worth a glance.',
      },
      reason: { type: 'string', description: 'One sentence explaining why this endpoint matters' },
      technologies: {
        type: 'array',
        items: { type: 'string' },
        description: 'Detected technologies (optional, e.g. ["express", "react"])',
      },
    },
    required: ['path', 'vuln_classes', 'priority', 'reason'],
  },
  run,
};
