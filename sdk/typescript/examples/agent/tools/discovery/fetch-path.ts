// fetch_path — one-shot HTTP probe. Returns status, content-type,
// selected headers, and a body snippet. Use this when the agent needs
// to look at a specific URL closely — granular, not for crawling.

import { fetchSafe } from '../../lib/http';
import { env } from '../../lib/env';
import { DiscoveryTool } from './types';

interface Args {
  path: string;
}

async function run(rawArgs: Record<string, unknown>): Promise<string> {
  const args = rawArgs as unknown as Args;
  if (typeof args.path !== 'string' || !args.path) {
    return 'ERROR: fetch_path requires a string `path` argument';
  }
  const url = `https://${env.target}${args.path}`;
  const resp = await fetchSafe(url);
  if (!resp) {
    return `ERROR: ${url} unreachable (network error or timeout)`;
  }
  const interesting: Record<string, string> = {};
  for (const k of ['content-type', 'server', 'x-powered-by', 'set-cookie', 'location', 'www-authenticate']) {
    if (resp.headers[k]) interesting[k] = resp.headers[k];
  }
  const body = resp.body.slice(0, 1500);
  return JSON.stringify(
    {
      status: resp.status,
      headers: interesting,
      body_snippet: body,
      body_truncated: resp.body.length > 1500,
    },
    null,
    2,
  );
}

export const fetchPath: DiscoveryTool = {
  name: 'fetch_path',
  description: 'Fetch a single URL path to inspect its status, content-type, key headers, and body snippet. Use when you want to look at one specific endpoint closely.',
  parameters: {
    type: 'object',
    properties: {
      path: { type: 'string', description: 'URL path to fetch (e.g. /api/users)' },
    },
    required: ['path'],
  },
  run,
};
