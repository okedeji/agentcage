/**
 * Judge handler — LLM-as-a-judge for payload safety review.
 *
 * The cage's payload-proxy POSTs `{payloads: [...]}` here when a
 * request is flagged for review (either per-request opt-in via the
 * X-Agentcage-Judge header, or cage-level via -judge-all-outbound).
 * Each payload describes one in-flight HTTP request the cage wants to
 * send to the target. This handler asks the LLM to classify each as
 * safe (forward) or unsafe (block).
 *
 * Wire format (matches internal/enforcement/judge.go and the SDK's
 * judge types — see sdk/typescript/src/types/judge.ts):
 *
 *   Request:
 *     POST /judge
 *     {"payloads": [
 *       {
 *         "cage_type": "exploitation",
 *         "vuln_class": "sqli",
 *         "assessment_id": "...",
 *         "method": "POST",
 *         "url": "https://target.com/api/users",
 *         "headers": { ... },
 *         "body": "...",
 *         "objective": "test /api/users for SQL injection on the id param",
 *         "agent_reason": "blind SQLi probe with time-based payload"
 *       },
 *       ...
 *     ]}
 *
 *   Response:
 *     {"results": [
 *       {"safe": true, "confidence": 0.9, "reason": "read-only probe"},
 *       ...
 *     ]}
 *
 * Order of results must match order of payloads.
 *
 * Environment:
 *   JUDGE_PROVIDER_URL  LLM endpoint for judge calls (default: same as LLM_PROVIDER_URL)
 *   LLM_PROVIDER_KEY    API key (reused from LLM handler)
 *   JUDGE_MODEL         Model to use (default: gpt-4o-mini — cheaper than the main LLM)
 *
 * agentcage config:
 *   judge:
 *     endpoint: "https://your-webhook-host:8082/judge"
 *
 *   Store the API key in Vault:
 *     agentcage vault put orchestrator/judge-api-key value=<WEBHOOK_API_KEY>
 */

import { IncomingMessage, ServerResponse } from 'node:http';
import {
  validatePayloads,
  validateResults,
  type JudgePayload,
  type JudgeResult,
} from '@agentcage/sdk';
import { readBody, sendJSON } from './index';

const PROVIDER_URL = process.env.JUDGE_PROVIDER_URL
  ?? process.env.LLM_PROVIDER_URL
  ?? 'https://api.openai.com/v1/chat/completions';
const PROVIDER_KEY = process.env.JUDGE_PROVIDER_KEY || process.env.LLM_PROVIDER_KEY || '';
const MODEL = process.env.JUDGE_MODEL ?? 'gpt-4o-mini';

if (!PROVIDER_KEY) {
  console.error('JUDGE_PROVIDER_KEY (or LLM_PROVIDER_KEY as fallback) is required');
  process.exit(1);
}

const SYSTEM_PROMPT = `You are a payload-safety judge for an authorized penetration testing system. Each request comes from a sandboxed pentest cage attacking an explicitly-authorized target. Decide whether forwarding the request is safe.

SAFE (allow): read-only probes, header inspections, low-volume credential checks against one endpoint, canary XSS / boundary-test injections that do not mutate state, most state-changing requests within authorized pentest scope. Lean toward SAFE — over-blocking defeats the purpose of the pentest.

UNSAFE (block):
- Mass destruction (DROP TABLE, DELETE without WHERE, account purge endpoints)
- Credential exfiltration intended for reuse on live systems
- Lateral movement outside the authorized target scope
- POSTs to attacker-controlled endpoints that would leak target data
- Anything obviously catastrophic and irreversible

Respond as JSON only: {"safe": true|false, "confidence": 0.0-1.0, "reason": "one sentence"}.`;

async function judgeOne(payload: JudgePayload): Promise<JudgeResult> {
  const userContent = [
    `vuln_class: ${payload.vulnClass}`,
    `cage_type: ${payload.cageType}`,
    `method: ${payload.method}`,
    `url: ${payload.url}`,
    `objective: ${payload.objective ?? '(none)'}`,
    `agent_reason: ${payload.agentReason ?? '(none)'}`,
    `body (truncated to 4KB):`,
    (payload.body ?? '').slice(0, 4096),
  ].join('\n');

  let resp: Response;
  try {
    resp = await fetch(PROVIDER_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${PROVIDER_KEY}`,
      },
      body: JSON.stringify({
        model: MODEL,
        messages: [
          { role: 'system', content: SYSTEM_PROMPT },
          { role: 'user', content: userContent },
        ],
        response_format: { type: 'json_object' },
        temperature: 0,
      }),
      signal: AbortSignal.timeout(30_000),
    });
  } catch (err: any) {
    // Network/timeout fail-closed: report unsafe with low confidence so
    // the proxy's policy decides what to do (block vs human review).
    return { safe: false, confidence: 0.3, reason: `judge LLM unreachable: ${err.message}` };
  }

  if (!resp.ok) {
    return { safe: false, confidence: 0.3, reason: `judge LLM returned HTTP ${resp.status}` };
  }

  let content = '';
  try {
    const data = (await resp.json()) as any;
    content = data.choices?.[0]?.message?.content ?? '';
  } catch {
    return { safe: false, confidence: 0.3, reason: 'judge LLM response not parseable as JSON' };
  }

  try {
    const parsed = JSON.parse(content);
    const safe = typeof parsed.safe === 'boolean' ? parsed.safe : false;
    const confidence = typeof parsed.confidence === 'number'
      ? Math.max(0, Math.min(1, parsed.confidence))
      : 0.5;
    const reason = typeof parsed.reason === 'string' && parsed.reason
      ? parsed.reason.slice(0, 500)
      : '(no reason given)';
    return { safe, confidence, reason };
  } catch {
    return { safe: false, confidence: 0.3, reason: 'judge LLM content not valid JSON' };
  }
}

export async function handleJudge(req: IncomingMessage, res: ServerResponse) {
  if (req.method !== 'POST') {
    sendJSON(res, 405, { error: 'POST required' });
    return;
  }

  let body: any;
  try {
    const raw = await readBody(req);
    body = JSON.parse(raw.toString());
  } catch {
    sendJSON(res, 400, { error: 'invalid JSON' });
    return;
  }

  let payloads: JudgePayload[];
  try {
    payloads = validatePayloads(body);
  } catch (err: any) {
    sendJSON(res, 400, { error: err.message });
    return;
  }
  if (payloads.length === 0) {
    sendJSON(res, 400, { error: 'no payloads to judge' });
    return;
  }
  if (payloads.length > 32) {
    sendJSON(res, 400, { error: 'too many payloads in one request (max 32)' });
    return;
  }

  // Evaluate each payload independently in parallel. One LLM call per
  // payload — simpler than batching and keeps the prompt focused.
  const results = await Promise.all(payloads.map(judgeOne));
  try {
    validateResults(results, payloads.length);
  } catch (err: any) {
    sendJSON(res, 500, { error: `internal error: ${err.message}` });
    return;
  }
  sendJSON(res, 200, { results });
}
