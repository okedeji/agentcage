import * as http from 'http';
import type { JudgePayload, JudgeResult } from '../types/judge';
import { validatePayloads, validateResults } from './validation';

export type EvaluateFn = (payloads: JudgePayload[]) => Promise<JudgeResult[]>;

export interface JudgeServerConfig {
  port?: number;
  path?: string;
  authToken?: string;
}

export function createJudgeServer(evaluate: EvaluateFn, config: JudgeServerConfig = {}): http.Server {
  const expectedPath = config.path ?? '/';
  const authToken = config.authToken;

  return http.createServer(async (req, res) => {
    if (req.method !== 'POST' || req.url !== expectedPath) {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'not found' }));
      return;
    }

    if (authToken) {
      const auth = req.headers['authorization'];
      if (auth !== `Bearer ${authToken}`) {
        res.writeHead(401, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'unauthorized' }));
        return;
      }
    }

    let body = '';
    for await (const chunk of req) {
      body += chunk;
      if (body.length > 10 * 1024 * 1024) {
        res.writeHead(413, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'request too large' }));
        return;
      }
    }

    try {
      const parsed = JSON.parse(body);
      const payloads = validatePayloads(parsed);
      const results = await evaluate(payloads);
      validateResults(results, payloads.length);

      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ results }));
    } catch (err: any) {
      const status = err.message?.includes('must') ? 400 : 500;
      res.writeHead(status, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: err.message }));
    }
  });
}
