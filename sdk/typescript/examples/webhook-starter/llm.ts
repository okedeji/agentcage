/**
 * LLM chat completion handler.
 *
 * Forwards OpenAI-compatible requests to the configured provider.
 * This is the place to add:
 *   - Model routing (map requests to different models based on cage type)
 *   - Provider switching (OpenAI, Anthropic via adapter, local models)
 *   - Fallback chains (try provider A, fall back to B on failure)
 *   - Rate limiting and cost controls
 *   - Request/response logging
 *
 *
 * agentcage requires the provider response to include
 * usage.total_tokens for metering and budget enforcement.
 * OpenAI includes this by default. If you swap in a custom
 * provider, make sure it does too.
 *
 * Environment:
 *   LLM_PROVIDER_URL  Target LLM API (default: https://api.openai.com/v1/chat/completions)
 *   LLM_PROVIDER_KEY  API key for the LLM provider
 *   LLM_MODEL         Model to use (default: gpt-4.1-mini)
 *
 * agentcage config:
 *   llm:
 *     endpoint: "https://your-webhook-host:8082/llm"
 *
 *   Store the API key in Vault:
 *     agentcage vault put orchestrator/llm-api-key value=<WEBHOOK_API_KEY>
 */

import { IncomingMessage, ServerResponse } from 'node:http';
import { readBody, sendJSON } from './index';

const PROVIDER_URL = process.env.LLM_PROVIDER_URL ?? 'https://api.openai.com/v1/chat/completions';
const PROVIDER_KEY = process.env.LLM_PROVIDER_KEY ?? '';
const MODEL = process.env.LLM_MODEL ?? 'gpt-5.5';

if (!PROVIDER_KEY) {
  console.error('LLM_PROVIDER_KEY is required');
  process.exit(1);
}

export async function handleLLM(req: IncomingMessage, res: ServerResponse) {
  let body: any;
  try {
    const raw = await readBody(req);
    body = JSON.parse(raw.toString());
  } catch {
    sendJSON(res, 400, { error: 'invalid JSON' });
    return;
  }

  body.model = MODEL;

  try {
    const providerResp = await fetch(PROVIDER_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${PROVIDER_KEY}`,
      },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(60_000),
    });

    const providerBody = await providerResp.text();

    if (providerResp.ok) {
      try {
        const parsed = JSON.parse(providerBody);
        if (!parsed.usage || !parsed.usage.total_tokens) {
          console.warn('WARNING: provider response missing usage.total_tokens — agentcage will reject this');
        }
      } catch {
        console.warn('WARNING: provider response is not valid JSON — agentcage will reject this');
      }
    }

    res.writeHead(providerResp.status, { 'Content-Type': 'application/json' });
    res.end(providerBody);
  } catch (err: any) {
    console.error('llm provider request failed:', err.message);
    sendJSON(res, 502, { error: `provider unreachable: ${err.message}` });
  }
}
