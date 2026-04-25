import * as http from 'http';
import * as https from 'https';

export interface VaultConfig {
  address: string;
  token: string;
}

const ORCHESTRATOR_PREFIX = 'secret/data/agentcage/orchestrator/';
const TARGET_PREFIX = 'secret/data/agentcage/target/';

export class VaultClient {
  private address: string;
  private token: string;

  constructor(config: VaultConfig) {
    this.address = config.address.replace(/\/$/, '');
    this.token = config.token;
  }

  async put(scope: string, key: string, value: string | Record<string, unknown>): Promise<void> {
    const path = this.resolvePath(scope, key);
    const data = typeof value === 'string' ? { value } : value;
    await this.request('POST', `/v1/${path}`, { data });
  }

  async get(scope: string, key: string): Promise<Record<string, unknown> | null> {
    const path = this.resolvePath(scope, key);
    try {
      const resp = await this.request('GET', `/v1/${path}`);
      const nested = resp?.data?.data;
      return nested ?? resp?.data ?? null;
    } catch {
      return null;
    }
  }

  async delete(scope: string, key: string): Promise<void> {
    const path = this.resolvePath(scope, key);
    await this.request('DELETE', `/v1/${path}`);
  }

  async list(scope: string): Promise<string[]> {
    const prefix = scope === 'orchestrator'
      ? 'secret/metadata/agentcage/orchestrator/'
      : 'secret/metadata/agentcage/target/';
    try {
      const resp = await this.request('LIST', `/v1/${prefix}`);
      return (resp?.data?.keys as string[]) ?? [];
    } catch {
      return [];
    }
  }

  private resolvePath(scope: string, key: string): string {
    if (scope === 'orchestrator') return ORCHESTRATOR_PREFIX + key;
    if (scope === 'target') return TARGET_PREFIX + key;
    throw new Error(`unknown scope "${scope}" (expected: orchestrator, target)`);
  }

  private request(method: string, urlPath: string, body?: unknown): Promise<any> {
    return new Promise((resolve, reject) => {
      const url = new URL(urlPath, this.address);
      const isHttps = url.protocol === 'https:';
      const mod = isHttps ? https : http;

      const payload = body ? JSON.stringify(body) : undefined;
      const httpMethod = method === 'LIST' ? 'GET' : method;

      const req = mod.request(url, {
        method: httpMethod,
        headers: {
          'X-Vault-Token': this.token,
          ...(payload ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) } : {}),
          ...(method === 'LIST' ? { 'X-Vault-List': 'true' } : {}),
        },
        timeout: 10000,
      }, (res) => {
        let data = '';
        res.on('data', (chunk) => { data += chunk; });
        res.on('end', () => {
          if (res.statusCode && res.statusCode >= 400) {
            reject(new Error(`vault ${method} ${urlPath}: HTTP ${res.statusCode}`));
            return;
          }
          try {
            resolve(data ? JSON.parse(data) : null);
          } catch {
            resolve(null);
          }
        });
      });

      req.on('error', (err) => reject(new Error(`vault ${method} ${urlPath}: ${err.message}`)));
      if (payload) req.write(payload);
      req.end();
    });
  }
}
