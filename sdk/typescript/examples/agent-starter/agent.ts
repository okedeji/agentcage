/**
 * LLM-driven security agent — uses the LLM to plan, craft payloads,
 * and analyze responses autonomously.
 *
 * The agent loop:
 *   1. Ask LLM to plan what to test based on discovered surface
 *   2. Execute the plan (send HTTP requests)
 *   3. Ask LLM to analyze responses for vulnerabilities
 *   4. Submit validated findings
 *   5. Ask LLM what to do next
 *   6. Repeat until LLM says done or orchestrator terminates
 *
 * Package and run:
 *   agentcage pack ./agent-starter
 *   agentcage run --agent agent-starter.cage --target example.com --customer-id cust-1
 */

import { AgentSDK, Severity, DirectiveInstruction } from '@agentcage/sdk';
import * as crypto from 'crypto';

// ── Environment ───────────────────────────────��──────────────

const targets = (process.env.AGENTCAGE_SCOPE ?? '').split(',').filter(Boolean);
const cageType = process.env.AGENTCAGE_CAGE_TYPE ?? 'discovery';
const objective = process.env.AGENTCAGE_OBJECTIVE ?? '';
const llmEndpoint = process.env.AGENTCAGE_LLM_ENDPOINT ?? '';
const llmAPIKey = process.env.AGENTCAGE_LLM_API_KEY ?? '';
const proofThreshold = parseFloat(process.env.AGENTCAGE_PROOF_THRESHOLD ?? '0.9');
const credentials = process.env.AGENTCAGE_TARGET_CREDENTIALS
  ? JSON.parse(process.env.AGENTCAGE_TARGET_CREDENTIALS)
  : null;

if (targets.length === 0) {
  console.error('No targets in AGENTCAGE_SCOPE');
  process.exit(1);
}
if (!llmEndpoint) {
  console.error('AGENTCAGE_LLM_ENDPOINT not set �� agent requires LLM access');
  process.exit(1);
}

console.log(`Agent starting. Type: ${cageType}, Targets: ${targets.join(', ')}`);
if (objective) console.log(`Objective: ${objective}`);
console.log(`LLM endpoint: ${llmEndpoint}`);

// ── SDK Setup ────────────────────────────────────────────────

const agent = new AgentSDK();
let terminated = false;

let redirectMessage = '';

agent.watchDirectives((directive: DirectiveInstruction) => {
  console.log(`Directive: ${directive.type}`);
  switch (directive.type) {
    case 'terminate':
      // Orchestrator wants us to stop. Shut down gracefully.
      console.log('Orchestrator requested termination.');
      terminated = true;
      agent.close();
      process.exit(0);
    case 'redirect':
      // Orchestrator wants us to change focus. The next LLM planning
      // call will include this message as updated instructions.
      console.log(`Redirected: ${directive.message}`);
      redirectMessage = directive.message ?? '';
      break;
    case 'continue':
      // Orchestrator confirms we should keep going. No action needed.
      break;
    case 'hold_result':
      // Response to a hold we requested. Handled inline where
      // requestHold() was called — this is just a notification
      // that the directive file was updated.
      console.log(`Hold ${directive.holdId} resolved: allowed=${directive.allowed}`);
      break;
  }
});

// ── LLM Client ───────────────────────────────────────────────

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
    signal: AbortSignal.timeout(30000),
  });

  if (!resp.ok) {
    throw new Error(`LLM returned ${resp.status}`);
  }

  const data = await resp.json() as any;
  return data.choices?.[0]?.message?.content ?? '';
}

// ── Helpers ──────────────────────────────────────────────────

async function fetchSafe(url: string, options?: RequestInit): Promise<{ status: number; body: string } | null> {
  try {
    const resp = await fetch(url, { ...options, signal: AbortSignal.timeout(10000) });
    const body = await resp.text();
    return { status: resp.status, body: body.slice(0, 8192) };
  } catch {
    return null;
  }
}

function findingId(): string {
  return crypto.randomUUID();
}

function parseSeverity(s: string): Severity {
  const map: Record<string, Severity> = {
    critical: Severity.Critical, high: Severity.High,
    medium: Severity.Medium, low: Severity.Low, info: Severity.Info,
  };
  return map[s.toLowerCase()] ?? Severity.Medium;
}

// ── Discovery Phase ──────────────────────────────────────────

interface TestTarget {
  endpoint: string;
  tests: string[];
  reason: string;
}

async function discoverSurface(target: string): Promise<TestTarget[]> {
  console.log(`\nDiscovering attack surface on ${target}...`);

  // Crawl common paths first to give the LLM something to work with.
  const paths = ['/', '/api', '/api/v1', '/login', '/admin', '/graphql',
    '/docs', '/swagger.json', '/health', '/search', '/register', '/profile'];
  const found: { path: string; status: number; snippet: string }[] = [];

  for (const path of paths) {
    if (terminated) break;
    const resp = await fetchSafe(`https://${target}${path}`);
    if (resp && resp.status < 500) {
      found.push({ path, status: resp.status, snippet: resp.body.slice(0, 500) });
    }
  }

  // Ask LLM to identify interesting endpoints from the crawl results.
  const analysis = await askLLM([
    {
      role: 'system',
      content: `You are a penetration testing assistant. Analyze discovered endpoints and suggest which ones to test for vulnerabilities. Be specific about what vulnerability types to try on each endpoint. Respond with JSON array: [{"endpoint": "/path", "tests": ["sqli", "xss", ...], "reason": "why"}]`,
    },
    {
      role: 'user',
      content: `Target: ${target}\nObjective: ${redirectMessage || objective || 'Full security assessment'}\n\nDiscovered endpoints:\n${found.map(f => `${f.path} (HTTP ${f.status}): ${f.snippet.slice(0, 200)}`).join('\n')}`,
    },
  ]);

  try {
    const plan = JSON.parse(analysis);
    console.log(`LLM identified ${plan.length} endpoints to test`);
    return plan;
  } catch {
    console.log('LLM response was not valid JSON, using discovered paths');
    return found.map(f => ({ endpoint: f.path, tests: ['sqli', 'xss'], reason: 'discovered' }));
  }
}

// ── Testing Phase ────────────────────────────────────────────

async function testEndpoint(target: string, endpoint: string, vulnClass: string): Promise<void> {
  // Ask LLM to generate a test payload.
  const payloadResponse = await askLLM([
    {
      role: 'system',
      content: `You are a penetration testing assistant. Generate a specific HTTP request to test for ${vulnClass} on the given endpoint. Respond with JSON: {"method": "GET|POST", "path": "/path", "headers": {}, "body": "...", "description": "what this tests"}`,
    },
    {
      role: 'user',
      content: `Target: https://${target}${endpoint}\nVulnerability class: ${vulnClass}\nGenerate a safe, non-destructive test payload.`,
    },
  ]);

  let testPlan: any;
  try {
    testPlan = JSON.parse(payloadResponse);
  } catch {
    console.log(`  Could not parse LLM payload for ${vulnClass} on ${endpoint}`);
    return;
  }

  // Execute the test.
  const url = `https://${target}${testPlan.path || endpoint}`;
  const resp = await fetchSafe(url, {
    method: testPlan.method || 'GET',
    headers: testPlan.headers || {},
    body: testPlan.body || undefined,
  });

  if (!resp) return;

  // Ask LLM to analyze the response for vulnerability indicators.
  const analysisResponse = await askLLM([
    {
      role: 'system',
      content: `You are a penetration testing assistant. Analyze this HTTP response and determine if it indicates a ${vulnClass} vulnerability. Respond with JSON: {"vulnerable": true/false, "severity": "critical|high|medium|low|info", "evidence": "what specifically indicates the vulnerability", "confidence": 0.0-1.0, "deterministic": true/false}. Set deterministic=true if re-running the same request would reproduce the same result.`,
    },
    {
      role: 'user',
      content: `Test: ${testPlan.description}\nRequest: ${testPlan.method} ${url}\n${testPlan.body ? `Body: ${testPlan.body}\n` : ''}\nResponse (HTTP ${resp.status}):\n${resp.body}`,
    },
  ]);

  let analysis: any;
  try {
    analysis = JSON.parse(analysisResponse);
  } catch {
    return;
  }

  if (!analysis.vulnerable || analysis.confidence < 0.7) return;

  const severity = parseSeverity(analysis.severity);
  const pocCommand = `curl ${testPlan.method === 'POST' ? `-X POST -d '${testPlan.body}'` : ''} '${url}'`;

  // When the LLM is highly confident and the test is deterministic
  // (re-running the same request would reproduce the finding), attach
  // a validation proof so the orchestrator can skip spawning a
  // validator cage when TrustAgentProof is enabled.
  const proof = analysis.confidence >= proofThreshold
    ? {
        reproductionSteps: pocCommand,
        confirmed: true,
        deterministic: analysis.deterministic !== false,
        validatorCageId: '',
        evidence: analysis.evidence,
      }
    : undefined;

  await agent.submitFinding({
    id: findingId(),
    severity,
    title: `${vulnClass.toUpperCase()} in ${endpoint}`,
    vulnClass,
    endpoint: url,
    description: analysis.evidence,
    evidence: {
      request: Buffer.from(`${testPlan.method} ${url}\n${testPlan.body ?? ''}`),
      response: Buffer.from(resp.body),
      poc: pocCommand,
    },
    validationProof: proof,
  });

  console.log(`  FINDING: ${severity} ${vulnClass} in ${endpoint} (confidence: ${analysis.confidence})`);

  // For critical findings, request operator hold.
  if (severity === Severity.Critical) {
    console.log('  Requesting hold for critical finding...');
    const hold = await agent.requestHold({
      holdId: findingId(),
      message: `Found ${vulnClass} in ${endpoint}: ${analysis.evidence}. Proceed with deeper testing?`,
    });
    console.log(`  Hold result: ${hold.allowed ? 'approved' : 'denied'}`);
  }
}

// ── Main Loop ────────────────────────────────────────────────

async function main() {
  for (const target of targets) {
    if (terminated) break;

    // Phase 1: Discover attack surface.
    const testPlan = await discoverSurface(target);

    // Phase 2: Test each endpoint.
    for (const item of testPlan) {
      if (terminated) break;
      const tests = item.tests || ['sqli', 'xss'];
      for (const vulnClass of tests) {
        if (terminated) break;
        console.log(`  Testing ${item.endpoint} for ${vulnClass}...`);
        await testEndpoint(target, item.endpoint, vulnClass);
      }
    }
  }

  console.log('\nAgent complete.');
  agent.close();
}

main().catch((err) => {
  console.error('Agent error:', err);
  agent.close();
  process.exit(1);
});
