/**
 * Reference judge implementation using Anthropic Claude.
 *
 * Usage:
 *   JUDGE_AUTH_TOKEN=secret ANTHROPIC_API_KEY=sk-... npx ts-node index.ts
 *
 * Then configure agentcage:
 *   judge:
 *     endpoint: http://localhost:8080
 */

import { createJudgeServer, JudgePayload, JudgeResult } from '@agentcage/sdk';

const ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY;
if (!ANTHROPIC_API_KEY) {
  console.error('ANTHROPIC_API_KEY is required');
  process.exit(1);
}

const AUTH_TOKEN = process.env.JUDGE_AUTH_TOKEN ?? 'dev-token';
const PORT = parseInt(process.env.PORT ?? '8080', 10);

async function evaluate(payloads: JudgePayload[]): Promise<JudgeResult[]> {
  return Promise.all(payloads.map(async (p) => {
    const prompt = `You are a security payload safety classifier for an authorized penetration test.

A cage of type "${p.cageType}" testing vulnerability class "${p.vulnClass}"
for assessment "${p.assessmentId}" wants to send this HTTP request:

${p.method} ${p.url}
${p.body ? `\nBody:\n${p.body}` : ''}

The target has authorized this assessment. Your job is to determine if
this specific payload is safe to send — meaning it tests the vulnerability
without causing permanent damage (no DROP TABLE, no disk wipes, no
exfiltration to external hosts).

Respond with ONLY a JSON object:
{"safe": true/false, "confidence": 0.0-1.0, "reason": "one sentence"}`;

    const resp = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': ANTHROPIC_API_KEY!,
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify({
        model: 'claude-sonnet-4-20250514',
        max_tokens: 150,
        messages: [{ role: 'user', content: prompt }],
      }),
    });

    if (!resp.ok) {
      console.error(`Anthropic API error: ${resp.status}`);
      return { safe: false, confidence: 1.0, reason: 'judge LLM call failed, blocking' };
    }

    const data = await resp.json() as any;
    const text = data.content?.[0]?.text ?? '';

    try {
      const result = JSON.parse(text);
      return {
        safe: !!result.safe,
        confidence: Math.max(0, Math.min(1, result.confidence ?? 0)),
        reason: result.reason ?? 'no reason provided',
      };
    } catch {
      return { safe: false, confidence: 1.0, reason: 'failed to parse LLM response, blocking' };
    }
  }));
}

const server = createJudgeServer(evaluate, { port: PORT, authToken: AUTH_TOKEN });
server.listen(PORT, () => {
  console.log(`Judge server listening on :${PORT}`);
  console.log(`Auth token: ${AUTH_TOKEN === 'dev-token' ? 'dev-token (set JUDGE_AUTH_TOKEN for production)' : '***'}`);
});
