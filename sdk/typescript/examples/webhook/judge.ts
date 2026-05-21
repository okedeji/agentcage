/**
 * Judge handler — passthrough to an OpenAI-compatible chat completion
 * provider.
 *
 * Agentcage's JudgeClient builds the request (system + user prompts,
 * tools[]: [submit_judgment], tool_choice: "required") and parses the
 * response. This handler is a thin forwarder: receives the chat
 * completion, overrides model with JUDGE_MODEL, sends to the provider,
 * returns the response verbatim.
 *
 * Want custom behavior (extra context, provider switching, per-customer
 * tuning)? Fork this file and modify the request before forwarding.
 * The wire contract is OpenAI chat completions in, OpenAI chat
 * completions out — keep the `tools[]` + `tool_choice` fields intact
 * and agentcage's parsing will continue to work. Remove them and
 * agentcage will treat every request as malformed → human review.
 *
 * Environment:
 *   JUDGE_PROVIDER_URL  LLM endpoint (default: same as LLM_PROVIDER_URL)
 *   JUDGE_PROVIDER_KEY  API key (default: LLM_PROVIDER_KEY)
 *   JUDGE_MODEL         Model name (default: gpt-4o-mini — cheaper than
 *                       LLM_MODEL since judge runs on every flagged request)
 *
 * agentcage config:
 *   judge:
 *     endpoint: "https://your-webhook-host:8082/judge"
 *
 *   Store the API key in Vault (same value as the LLM key, since both
 *   routes share WEBHOOK_API_KEY):
 *     agentcage vault put orchestrator/judge-api-key value=<WEBHOOK_API_KEY>
 */

import { IncomingMessage, ServerResponse } from 'node:http';
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

  // Webhook decides the model so operators can use a cheaper model for
  // judge than for the main LLM. Caller can request a model but we
  // override — same pattern as the /llm route.
  body.model = MODEL;

  try {
    const providerResp = await fetch(PROVIDER_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${PROVIDER_KEY}`,
      },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(30_000),
    });

    const providerBody = await providerResp.text();
    res.writeHead(providerResp.status, { 'Content-Type': 'application/json' });
    res.end(providerBody);
  } catch (err: any) {
    console.error('judge provider request failed:', err.message);
    sendJSON(res, 502, { error: `provider unreachable: ${err.message}` });
  }
}
