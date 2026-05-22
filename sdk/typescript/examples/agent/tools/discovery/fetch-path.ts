// fetch_path — one-shot HTTP probe. Returns status, content-type,
// selected headers, and a body view tuned to the response type:
// JS/CSS are scanned for URL-like strings (the only signal the agent
// usually wants from a minified bundle); binaries return metadata
// only; HTML/JSON/text keep a snippet of the raw body.

import { fetchSafe } from '../../lib/http';
import { env } from '../../lib/env';
import { DiscoveryTool } from './types';

interface Args {
  path: string;
}

const TEXT_SNIPPET_BYTES = 1500;
const MAX_EXTRACTED_URLS = 40;

// Matches quoted absolute paths in JS/CSS source: things like "/api/users",
// '/auth/login', `/static/x.js`. Strict enough to skip random punctuation
// and common false positives like a lone "/" or filename-only ".css".
const URL_LITERAL = /['"`](\/[A-Za-z0-9_\-\/\.\{\}:?=&%]{2,120})['"`]/g;

function extractURLs(body: string): string[] {
  const seen = new Set<string>();
  for (const match of body.matchAll(URL_LITERAL)) {
    const p = match[1];
    // Drop bare extensions / single-segment static asset names — the LLM
    // already understands "this is a Next.js app," it doesn't need
    // /favicon.ico flagged again.
    if (/^\/[^\/]{0,2}$/.test(p)) continue;
    if (/^\/[a-z0-9_\-]+\.(css|js|map|woff2?|ttf|png|jpg|jpeg|gif|ico|svg|webp)$/i.test(p)) continue;
    seen.add(p);
    if (seen.size >= MAX_EXTRACTED_URLS) break;
  }
  return [...seen];
}

function classifyContentType(ct: string): 'js' | 'css' | 'binary' | 'text' {
  const t = ct.toLowerCase();
  if (t.includes('javascript') || t.includes('ecmascript')) return 'js';
  if (t.includes('text/css')) return 'css';
  if (
    t.startsWith('image/') ||
    t.startsWith('video/') ||
    t.startsWith('audio/') ||
    t.startsWith('font/') ||
    t.includes('octet-stream') ||
    t.includes('font-woff')
  ) {
    return 'binary';
  }
  return 'text';
}

async function run(rawArgs: Record<string, unknown>): Promise<string> {
  const args = rawArgs as unknown as Args;
  if (typeof args.path !== 'string' || !args.path) {
    return 'ERROR: fetch_path requires a string `path` argument';
  }
  const url = `https://${env.target}${args.path}`;
  const result = await fetchSafe(url);
  if (!result.ok) {
    return `ERROR: ${url} fetch failed: ${result.error}`;
  }
  const resp = result.response;

  const interesting: Record<string, string> = {};
  for (const k of ['content-type', 'server', 'x-powered-by', 'set-cookie', 'location', 'www-authenticate']) {
    if (resp.headers[k]) interesting[k] = resp.headers[k];
  }

  const kind = classifyContentType(interesting['content-type'] ?? '');
  const out: Record<string, unknown> = {
    status: resp.status,
    headers: interesting,
    body_size: resp.body.length,
  };

  switch (kind) {
    case 'js':
    case 'css': {
      const urls = extractURLs(resp.body);
      out.body_kind = kind;
      out.extracted_urls = urls;
      out.note = `Body omitted (${kind}); extracted ${urls.length} URL-like strings up to ${MAX_EXTRACTED_URLS}.`;
      break;
    }
    case 'binary':
      out.body_kind = 'binary';
      out.note = 'Body omitted (non-text content-type).';
      break;
    default:
      out.body_kind = 'text';
      out.body_snippet = resp.body.slice(0, TEXT_SNIPPET_BYTES);
      out.body_truncated = resp.body.length > TEXT_SNIPPET_BYTES;
  }

  return JSON.stringify(out, null, 2);
}

export const fetchPath: DiscoveryTool = {
  name: 'fetch_path',
  description: 'Fetch a single URL path. For HTML/JSON/text responses you get status, headers, and a body snippet. For JavaScript or CSS responses you get URL-like strings extracted from the body (more useful than raw minified source). For images/fonts/binaries you get headers and size only.',
  parameters: {
    type: 'object',
    properties: {
      path: { type: 'string', description: 'URL path to fetch (e.g. /api/users)' },
    },
    required: ['path'],
  },
  run,
};
