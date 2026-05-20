// recon_scan — nuclei with tech, osint, default-paths, and exposure
// templates. Identifies the target's technology stack, finds common
// default-installed paths, and surfaces low-hanging exposures
// (.git/.env/etc.). Use early to understand what the target is and
// what obvious surface exists.

import { runCmd } from '../../lib/cmd';
import { auth } from '../../lib/auth';
import { env } from '../../lib/env';
import { DiscoveryTool } from './types';

interface Args {
  path: string;
}

interface NucleiHit {
  templateID: string;
  name: string;
  severity: string;
  matchedAt: string;
}

function parseHits(stdout: string): NucleiHit[] {
  const hits: NucleiHit[] = [];
  for (const line of stdout.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    try {
      const parsed = JSON.parse(trimmed);
      hits.push({
        templateID: parsed['template-id'] ?? parsed.templateID ?? 'unknown',
        name: parsed.info?.name ?? '',
        severity: parsed.info?.severity ?? 'info',
        matchedAt: parsed['matched-at'] ?? '',
      });
    } catch {
      // Non-JSON line; nuclei sometimes emits status lines.
    }
  }
  return hits;
}

async function run(rawArgs: Record<string, unknown>): Promise<string> {
  const args = rawArgs as unknown as Args;
  if (typeof args.path !== 'string' || !args.path) {
    return 'ERROR: recon_scan requires a string `path` argument';
  }
  const url = `https://${env.target}${args.path}`;
  const nucleiArgs = [
    '-u', url,
    '-tags', 'tech,osint,default-paths,exposure',
    '-silent', '-jsonl', '-timeout', '15',
  ];
  if (auth?.type === 'header') nucleiArgs.push('-H', `${auth.name}: ${auth.value}`);
  if (auth?.type === 'cookie') nucleiArgs.push('-H', `Cookie: ${auth.name}=${auth.value}`);

  const { stdout, stderr } = await runCmd('nuclei', nucleiArgs, 120_000);
  const hits = parseHits(stdout);

  if (hits.length === 0) {
    return `nuclei recon found no matches against ${args.path} (stderr: ${stderr.slice(0, 200)})`;
  }
  const lines = hits
    .slice(0, 40)
    .map((h) => `  [${h.severity}] ${h.templateID} — ${h.name} @ ${h.matchedAt}`)
    .join('\n');
  return `nuclei recon hits on ${args.path} (${hits.length}):\n${lines}`;
}

export const reconScan: DiscoveryTool = {
  name: 'recon_scan',
  description: 'Run nuclei with tech-detection / OSINT / default-paths / exposure templates against a path. Identifies the technology stack and surfaces common exposed files and default-installed routes. Good early in discovery to understand what the target is.',
  parameters: {
    type: 'object',
    properties: {
      path: { type: 'string', description: 'URL path to scan (typically / or a known endpoint)' },
    },
    required: ['path'],
  },
  run,
};
