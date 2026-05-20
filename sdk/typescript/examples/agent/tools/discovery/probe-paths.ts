// probe_paths — fast parallel HTTP probing of LLM-generated path
// candidates via httpx. Use this when you have enough context (from
// recon_scan, fetch_path, or crawl) to guess specific paths worth
// checking. Returns status, content-length, title, and detected
// technology per URL.
//
// Why not just call fetch_path in a loop? httpx batches in parallel
// with built-in tech-detection and is the right primitive for "I have
// 20 candidate paths, tell me what's at each one." Beats 20 serial
// round-trips.

import { mkdtempSync, writeFileSync, readFileSync, existsSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { runCmd } from '../../lib/cmd';
import { auth } from '../../lib/auth';
import { env } from '../../lib/env';
import { DiscoveryTool } from './types';

interface Args {
  paths: string[];
}

interface HttpxHit {
  url?: string;
  status_code?: number;
  content_length?: number;
  title?: string;
  tech?: string[];
}

async function run(rawArgs: Record<string, unknown>): Promise<string> {
  const args = rawArgs as unknown as Args;
  if (!Array.isArray(args.paths) || args.paths.length === 0) {
    return 'ERROR: probe_paths requires a non-empty `paths` array';
  }
  const paths = args.paths
    .filter((p): p is string => typeof p === 'string' && p.startsWith('/'))
    .slice(0, 50);
  if (paths.length === 0) {
    return 'ERROR: probe_paths needs paths starting with / (got none after filtering)';
  }

  const tmp = mkdtempSync(join(tmpdir(), 'httpx-'));
  const inputPath = join(tmp, 'urls.txt');
  const outputPath = join(tmp, 'out.jsonl');
  const urls = paths.map((p) => `https://${env.target}${p}`).join('\n');
  writeFileSync(inputPath, urls);

  const httpxArgs = [
    '-l', inputPath,
    '-o', outputPath,
    '-json',
    '-status-code',
    '-content-length',
    '-title',
    '-tech-detect',
    '-follow-redirects',
    '-silent',
    '-no-color',
    '-timeout', '10',
  ];
  if (auth?.type === 'header') httpxArgs.push('-H', `${auth.name}: ${auth.value}`);
  if (auth?.type === 'cookie') httpxArgs.push('-H', `Cookie: ${auth.name}=${auth.value}`);

  const { stderr } = await runCmd('httpx', httpxArgs, 60_000);

  if (!existsSync(outputPath)) {
    return `httpx produced no output (stderr: ${stderr.slice(0, 200)})`;
  }
  const hits: HttpxHit[] = [];
  for (const line of readFileSync(outputPath, 'utf8').split('\n')) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    try {
      hits.push(JSON.parse(trimmed));
    } catch {
      // skip malformed line
    }
  }

  if (hits.length === 0) {
    return `httpx returned no responsive paths from ${paths.length} candidates`;
  }
  const hostPrefix = `https://${env.target}`;
  const lines = hits.map((h) => {
    const path = (h.url ?? '').startsWith(hostPrefix) ? h.url!.slice(hostPrefix.length) : h.url ?? '?';
    const status = h.status_code ?? '?';
    const len = h.content_length ?? '?';
    const title = h.title ? ` "${h.title.slice(0, 60)}"` : '';
    const tech = h.tech && h.tech.length > 0 ? ` [${h.tech.join(',')}]` : '';
    return `  ${path} → ${status} (${len}B)${title}${tech}`;
  });
  return `Probed ${paths.length} candidates, ${hits.length} responded:\n${lines.join('\n')}`;
}

export const probePaths: DiscoveryTool = {
  name: 'probe_paths',
  description: 'Probe a list of candidate URL paths in parallel via httpx. Returns status, content-length, title, and detected tech for each responding path. Use this when you have generated specific path candidates from context (recon_scan output, fetch_path snippets, the tech stack you identified) — much faster and richer than calling fetch_path one path at a time.',
  parameters: {
    type: 'object',
    properties: {
      paths: {
        type: 'array',
        items: { type: 'string' },
        description: 'Candidate URL paths to probe (e.g. ["/api/v1/users", "/api/v1/products", "/admin/dashboard"]). Up to 50 per call; must start with /.',
      },
    },
    required: ['paths'],
  },
  run,
};
