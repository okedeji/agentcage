import * as crypto from 'crypto';
import { VaultClient } from './vault';

export interface ApiKeyInfo {
  name: string;
  key: string;
  keyHash: string;
}

const ACCESS_KEYS_PATH = 'access-keys';

export class AccessClient {
  private vault: VaultClient;

  constructor(vault: VaultClient) {
    this.vault = vault;
  }

  async createKey(name: string): Promise<ApiKeyInfo> {
    const existing = await this.listKeys();
    if (existing.some((k) => k.name === name)) {
      throw new Error(`key with name "${name}" already exists`);
    }

    const keyBytes = crypto.randomBytes(32);
    const key = keyBytes.toString('hex');
    const keyHash = 'sha256:' + crypto.createHash('sha256').update(key).digest('hex');

    const keys = [...existing, { name, keyHash }];
    await this.vault.put('orchestrator', ACCESS_KEYS_PATH, { keys: JSON.stringify(keys) });

    return { name, key, keyHash };
  }

  async listKeys(): Promise<Array<{ name: string; keyHash: string }>> {
    const data = await this.vault.get('orchestrator', ACCESS_KEYS_PATH);
    if (!data || !data.keys) return [];
    try {
      return JSON.parse(data.keys as string);
    } catch {
      return [];
    }
  }

  async revokeKey(name: string): Promise<void> {
    const existing = await this.listKeys();
    const filtered = existing.filter((k) => k.name !== name);
    if (filtered.length === existing.length) {
      throw new Error(`no key found with name "${name}"`);
    }
    await this.vault.put('orchestrator', ACCESS_KEYS_PATH, { keys: JSON.stringify(filtered) });
  }
}
