import * as http from 'http';
import type { ProvisionResult, StatusResult } from '../types/provisioner';
import { validateProvisionResult, validateStatusResult, parseHostId } from './validation';

export interface ProvisionerHandler {
  provision(): Promise<ProvisionResult>;
  drain(hostId: string): Promise<void>;
  terminate(hostId: string): Promise<void>;
  status(hostId: string): Promise<StatusResult>;
}

export interface ProvisionerServerConfig {
  port?: number;
  authToken?: string;
}

export function createProvisionerServer(
  handler: ProvisionerHandler,
  config: ProvisionerServerConfig = {},
): http.Server {
  const authToken = config.authToken;

  return http.createServer(async (req, res) => {
    if (req.method !== 'POST') {
      res.writeHead(405, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'method not allowed' }));
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
    }

    let parsed: any = {};
    if (body.trim()) {
      try {
        parsed = JSON.parse(body);
      } catch {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'invalid JSON' }));
        return;
      }
    }

    try {
      switch (req.url) {
        case '/provision': {
          const result = await handler.provision();
          validateProvisionResult(result);
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            host_id: result.hostId,
            address: result.address,
            vcpus: result.vcpus,
            memory_mb: result.memoryMb,
            cage_slots: result.cageSlots,
          }));
          break;
        }
        case '/drain': {
          const hostId = parseHostId(parsed);
          await handler.drain(hostId);
          res.writeHead(200);
          res.end();
          break;
        }
        case '/terminate': {
          const hostId = parseHostId(parsed);
          await handler.terminate(hostId);
          res.writeHead(200);
          res.end();
          break;
        }
        case '/status': {
          const hostId = parseHostId(parsed);
          const result = await handler.status(hostId);
          validateStatusResult(result);
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            host_id: result.hostId,
            ready: result.ready,
          }));
          break;
        }
        default:
          res.writeHead(404, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'not found' }));
      }
    } catch (err: any) {
      const status = err.message?.includes('must') ? 400 : 500;
      res.writeHead(status, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: err.message }));
    }
  });
}
