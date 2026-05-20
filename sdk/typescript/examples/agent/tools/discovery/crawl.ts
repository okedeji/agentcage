// crawl — katana JS-aware web crawler. Renders JavaScript via headless
// chromium and extracts URLs from rendered DOM, network requests, and
// script bundles. Use this for SPAs / dynamic sites where plain HTTP
// crawling misses routes the client-side router resolves at runtime.

import { runCmd } from '../../lib/cmd';
import { auth } from '../../lib/auth';
import { env } from '../../lib/env';
import { DiscoveryTool } from './types';

interface Args {
  seed_path: string;
  max_depth?: number;
}

async function run(rawArgs: Record<string, unknown>): Promise<string> {
  const args = rawArgs as unknown as Args;
  if (typeof args.seed_path !== 'string' || !args.seed_path) {
    return 'ERROR: crawl requires a string `seed_path` argument';
  }
  const depth = Math.max(1, Math.min(args.max_depth ?? 2, 4));
  const url = `https://${env.target}${args.seed_path}`;
  const katanaArgs = [
    '-u', url,
    '-d', String(depth),
    '-jc',
    '-silent',
    '-timeout', '20',
  ];
  if (auth?.type === 'header') katanaArgs.push('-H', `${auth.name}: ${auth.value}`);
  if (auth?.type === 'cookie') katanaArgs.push('-H', `Cookie: ${auth.name}=${auth.value}`);

  const { stdout, stderr } = await runCmd('katana', katanaArgs, 120_000);
  const lines = stdout.split('\n').map((l) => l.trim()).filter(Boolean);
  // katana emits absolute URLs; strip host so the agent sees paths consistent
  // with what other tools accept.
  const hostPrefix = `https://${env.target}`;
  const paths = Array.from(
    new Set(
      lines
        .filter((l) => l.startsWith(hostPrefix))
        .map((l) => l.slice(hostPrefix.length))
        .filter(Boolean),
    ),
  ).slice(0, 80);

  if (paths.length === 0) {
    return `katana returned no in-scope paths (stderr: ${stderr.slice(0, 200)})`;
  }
  return `Discovered ${paths.length} paths from ${args.seed_path} (depth=${depth}):\n${paths.join('\n')}`;
}

export const crawl: DiscoveryTool = {
  name: 'crawl',
  description: 'Run a JavaScript-aware web crawler (katana) from a seed path. Renders pages via headless chromium and extracts URLs from rendered DOM, network requests, and JS bundles. Best for SPAs and dynamic sites where plain HTTP crawling misses routes.',
  parameters: {
    type: 'object',
    properties: {
      seed_path: { type: 'string', description: 'URL path to start crawling from (e.g. / or /app)' },
      max_depth: { type: 'integer', description: 'Crawl depth, 1-4 (default 2). Higher = more thorough but slower.' },
    },
    required: ['seed_path'],
  },
  run,
};
