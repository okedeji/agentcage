/**
 * agentcage webhook gateway — starter template.
 *
 * Routes incoming requests to the appropriate handler. Each handler
 * lives in its own file. Add new webhooks (judge, provisioner, etc.)
 * by creating a handler file and wiring a route below.
 *
 * Environment:
 *   WEBHOOK_API_KEY   API key that agentcage must send to authenticate
 *   PORT              Listen port (default: 8082)
 *
 * Deploy:
 *   npm install && npm run build && npm start
 *
 * Then configure agentcage with endpoint pointing to the
 * appropriate route (e.g. https://your-host:8082/llm).
 * See each handler file for config details.
 */

import { createServer, IncomingMessage, ServerResponse } from 'node:http';
import { handleLLM } from './llm';

const API_KEY = process.env.WEBHOOK_API_KEY ?? '';
const PORT = parseInt(process.env.PORT ?? '8082', 10);

if (!API_KEY) {
  console.error('WEBHOOK_API_KEY is required');
  process.exit(1);
}

export function readBody(req: IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

export function sendJSON(res: ServerResponse, status: number, body: unknown) {
  const data = JSON.stringify(body);
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(data);
}

const server = createServer(async (req, res) => {
  if (req.method === 'GET' && req.url === '/health') {
    sendJSON(res, 200, { status: 'ok' });
    return;
  }

  // Auth — shared across all routes.
  const apiKey = req.headers['x-api-key'] ?? '';
  if (apiKey !== API_KEY) {
    sendJSON(res, 401, { error: 'invalid api key' });
    return;
  }

  const url = req.url ?? '/';

  if (url.startsWith('/llm')) {
    await handleLLM(req, res);
    return;
  }

  sendJSON(res, 404, { error: 'not found' });
});

server.listen(PORT, () => {
  console.log(`agentcage webhook gateway listening on :${PORT}`);
  console.log(`Routes: /llm`);
});
