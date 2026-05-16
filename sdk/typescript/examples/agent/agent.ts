/**
 * Discovery agent for agentcage.
 *
 * Maps the target's attack surface and submits discovered endpoints
 * as findings. The assessment coordinator uses these to plan which
 * exploitation cages to spawn next.
 *
 * This agent only runs in discovery cages. Exploitation and
 * validation agents are separate.
 */

import { AgentSDK, Severity, DirectiveInstruction } from '@agentcage/sdk';
import * as crypto from 'crypto';

// ── Environment ─────────────────────────────────────────────

const targets = (process.env.AGENTCAGE_SCOPE ?? '').split(',').filter(Boolean);
const llmEndpoint = process.env.AGENTCAGE_LLM_ENDPOINT ?? '';
const llmAPIKey = process.env.AGENTCAGE_LLM_API_KEY ?? '';
const objective = process.env.AGENTCAGE_OBJECTIVE ?? '';

if (targets.length === 0) {
  console.error('No targets in AGENTCAGE_SCOPE');
  process.exit(1);
}
if (!llmEndpoint) {
  console.error('AGENTCAGE_LLM_ENDPOINT not set');
  process.exit(1);
}

console.log(`Agent starting. Targets: ${targets.join(', ')}`);
console.log(`LLM endpoint: ${llmEndpoint}`);

// ── SDK ─────────────────────────────────────────────────────

const agent = new AgentSDK();
let terminated = false;

agent.watchDirectives((directive: DirectiveInstruction) => {
  if (directive.type === 'terminate') {
    terminated = true;
    agent.close();
    process.exit(0);
  }
});

// ── LLM ─────────────────────────────────────────────────────

interface LLMMessage {
  role: 'system' | 'user' | 'assistant';
  content: string;
}

async function askLLM(messages: LLMMessage[]): Promise<string> {
  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  if (llmAPIKey) {
    headers['x-api-key'] = llmAPIKey;
  }
  const resp = await fetch(llmEndpoint, {
    method: 'POST',
    headers,
    body: JSON.stringify({ messages }),
    signal: AbortSignal.timeout(60000),
  });
  if (!resp.ok) {
    throw new Error(`LLM returned ${resp.status}`);
  }
  const data = await resp.json() as any;
  return data.choices?.[0]?.message?.content ?? '';
}

// Strip markdown code fences that LLMs commonly wrap JSON in.
function extractJSON(raw: string): any {
  let text = raw.trim();
  const fenceStart = text.indexOf('```');
  if (fenceStart >= 0) {
    const afterFence = text.indexOf('\n', fenceStart);
    const fenceEnd = text.lastIndexOf('```');
    if (afterFence >= 0 && fenceEnd > afterFence) {
      text = text.slice(afterFence + 1, fenceEnd).trim();
    }
  }
  return JSON.parse(text);
}

// ── HTTP ────────────────────────────────────────────────────

interface HttpResponse {
  status: number;
  headers: Record<string, string>;
  body: string;
}

async function fetchSafe(url: string): Promise<HttpResponse | null> {
  try {
    const resp = await fetch(url, { signal: AbortSignal.timeout(10000), redirect: 'follow' });
    const body = await resp.text();
    const headers: Record<string, string> = {};
    resp.headers.forEach((v, k) => { headers[k] = v; });
    return { status: resp.status, headers, body: body.slice(0, 8192) };
  } catch {
    return null;
  }
}

// ── Step 1: Seed crawl ─────────────────────────────────────

interface SeedData {
  homepage: HttpResponse | null;
  robots: HttpResponse | null;
  sitemap: HttpResponse | null;
}

async function seedCrawl(target: string): Promise<SeedData> {
  console.log('Fetching seed pages (/, /robots.txt, /sitemap.xml)...');
  const [homepage, robots, sitemap] = await Promise.all([
    fetchSafe(`https://${target}/`),
    fetchSafe(`https://${target}/robots.txt`),
    fetchSafe(`https://${target}/sitemap.xml`),
  ]);
  return { homepage, robots, sitemap };
}

// ── Step 2: Ask LLM what to crawl ──────────────────────────

async function planCrawl(target: string, seed: SeedData): Promise<string[]> {
  console.log('Asking LLM to plan crawl paths...');

  let seedSummary = '';
  if (seed.homepage) {
    seedSummary += `Homepage (HTTP ${seed.homepage.status}):\n${seed.homepage.body.slice(0, 2000)}\n\n`;
    seedSummary += `Response headers: ${JSON.stringify(seed.homepage.headers)}\n\n`;
  } else {
    seedSummary += 'Homepage: unreachable\n\n';
  }
  if (seed.robots && seed.robots.status === 200) {
    seedSummary += `robots.txt:\n${seed.robots.body.slice(0, 2000)}\n\n`;
  }
  if (seed.sitemap && seed.sitemap.status === 200) {
    seedSummary += `sitemap.xml:\n${seed.sitemap.body.slice(0, 2000)}\n\n`;
  }

  const response = await askLLM([
    {
      role: 'system',
      content: `You are a penetration testing assistant performing attack surface discovery.

Based on the target's homepage, robots.txt, and sitemap, determine what paths to crawl next. Analyze:
- Links and routes visible in the HTML
- Framework/technology indicators (React, Express, Django, WordPress, etc.)
- API patterns suggested by the page structure
- Paths mentioned in robots.txt (disallowed paths are especially interesting)
- URLs in the sitemap
- Common paths for the detected technology stack

Return a JSON array of paths to crawl (max 50):
["/api/v1", "/login", "/admin", ...]

Only include paths likely to exist on THIS target based on what you see. Do not guess generic paths that have no evidence.`,
    },
    {
      role: 'user',
      content: `Target: ${target}\nObjective: ${objective || 'Full security assessment'}\n\n${seedSummary}`,
    },
  ]);

  try {
    const paths = extractJSON(response);
    if (Array.isArray(paths)) {
      const filtered = paths.filter((p: any) => typeof p === 'string' && p.startsWith('/')).slice(0, 50);
      if (filtered.length > 0) return filtered;
    }
  } catch {
    console.log('LLM response was not valid JSON, raw:', response.slice(0, 200));
  }

  const links = extractLinks(seed.homepage?.body ?? '');
  if (links.length > 0) {
    console.log(`Extracted ${links.length} links from homepage HTML`);
    return links;
  }

  console.log('No paths from LLM or HTML, using minimal seed list');
  return ['/api', '/login', '/admin', '/docs', '/graphql', '/health', '/search', '/sitemap.xml'];
}

function extractLinks(html: string): string[] {
  const paths: string[] = [];
  const seen = new Set<string>();
  const pattern = /href=["']([^"']+)["']/g;
  let match;
  while ((match = pattern.exec(html)) !== null) {
    let href = match[1];
    if (href.startsWith('/') && !href.startsWith('//') && !seen.has(href)) {
      seen.add(href);
      paths.push(href);
    }
  }
  return paths.slice(0, 50);
}

// ── Step 3: Crawl the planned paths ────────────────────────

interface Endpoint {
  path: string;
  status: number;
  contentType: string;
  headers: Record<string, string>;
  snippet: string;
}

async function crawlPaths(target: string, paths: string[]): Promise<Endpoint[]> {
  const endpoints: Endpoint[] = [];

  for (const path of paths) {
    if (terminated) break;
    const resp = await fetchSafe(`https://${target}${path}`);
    if (resp && resp.status < 500) {
      endpoints.push({
        path,
        status: resp.status,
        contentType: resp.headers['content-type'] ?? '',
        headers: resp.headers,
        snippet: resp.body.slice(0, 500),
      });
    }
  }

  return endpoints;
}

// ── Step 4: Ask LLM to analyze the surface ─────────────────

interface SurfaceEntry {
  endpoint: string;
  technologies: string[];
  vuln_classes: string[];
  priority: string;
  reason: string;
}

async function analyzeSurface(target: string, seed: SeedData, endpoints: Endpoint[]): Promise<SurfaceEntry[]> {
  console.log('Asking LLM to analyze attack surface...');

  const endpointSummary = endpoints.map(e =>
    `${e.path} (HTTP ${e.status}, ${e.contentType}): ${e.snippet.slice(0, 200)}`
  ).join('\n');

  const headerSummary = seed.homepage
    ? `Homepage headers: ${JSON.stringify(seed.homepage.headers)}`
    : '';

  const response = await askLLM([
    {
      role: 'system',
      content: `You are a penetration testing assistant. Analyze the crawled endpoints and produce a prioritized attack surface map.

For each interesting endpoint, identify:
- Technologies and frameworks detected
- Vulnerability classes to test: sqli, xss, ssrf, idor, auth-bypass, rce, lfi, open-redirect, cors, csrf, info-disclosure, broken-auth, rate-limit-bypass, etc.
- Priority: high, medium, or low based on attack potential

Focus on endpoints that:
- Accept user input (query params, POST bodies, file uploads)
- Handle authentication or authorization
- Return sensitive data
- Expose internal functionality or debug info
- Have misconfigured headers or CORS

Skip static assets, generic error pages, and marketing content.

Respond with ONLY a JSON array:
[{"endpoint": "/path", "technologies": ["express"], "vuln_classes": ["sqli", "xss"], "priority": "high", "reason": "why this is interesting"}]`,
    },
    {
      role: 'user',
      content: `Target: ${target}\nObjective: ${objective || 'Full security assessment'}\n${headerSummary}\n\nDiscovered ${endpoints.length} endpoints:\n${endpointSummary}`,
    },
  ]);

  try {
    const parsed = extractJSON(response);
    if (Array.isArray(parsed) && parsed.length > 0) return parsed;
  } catch {
    console.log('LLM analysis was not valid JSON, raw:', response.slice(0, 200));
  }

  console.log('Falling back to raw endpoints as surface map');
  return endpoints
    .filter(e => e.status === 200)
    .map(e => ({
      endpoint: e.path,
      technologies: [],
      vuln_classes: ['unknown'],
      priority: 'medium',
      reason: `HTTP ${e.status}, ${e.contentType}`,
    }));
}

// ── Step 5: Submit findings ────────────────────────────────

async function submitSurface(target: string, surface: SurfaceEntry[]): Promise<void> {
  for (const entry of surface) {
    if (terminated) break;

    await agent.submitFinding({
      id: crypto.randomUUID(),
      severity: Severity.Info,
      title: `Discovered: ${entry.endpoint}`,
      vulnClass: 'surface',
      endpoint: `https://${target}${entry.endpoint}`,
      description: `${entry.reason}. Technologies: ${entry.technologies.join(', ') || 'unknown'}. Suggested tests: ${entry.vuln_classes.join(', ')}. Priority: ${entry.priority}.`,
      evidence: {
        metadata: {
          priority: entry.priority,
          vuln_classes: entry.vuln_classes.join(','),
          technologies: entry.technologies.join(','),
        },
      },
    });

    console.log(`  [${entry.priority}] ${entry.endpoint} → ${entry.vuln_classes.join(', ')}`);
  }
}

// ── Main ────────────────────────────────────────────────────

async function main() {
  for (const target of targets) {
    if (terminated) break;

    console.log(`\n── Discovering ${target} ──`);

    const seed = await seedCrawl(target);
    const paths = await planCrawl(target, seed);
    console.log(`LLM planned ${paths.length} paths to crawl`);

    const endpoints = await crawlPaths(target, paths);
    console.log(`${endpoints.length} live endpoints found`);

    if (endpoints.length === 0) {
      console.log('No live endpoints, target may be unreachable');
      continue;
    }

    const surface = await analyzeSurface(target, seed, endpoints);
    console.log(`${surface.length} interesting endpoints identified`);

    await submitSurface(target, surface);
  }

  console.log('\nDiscovery complete.');
  agent.close();
}

main().catch((err) => {
  console.error('Agent error:', err);
  agent.close();
  process.exit(1);
});
