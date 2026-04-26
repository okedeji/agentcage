import * as grpc from '@grpc/grpc-js';
import { callUnary } from './client';
import type { PingResponse, HealthResponse } from '../types/control';

export class ControlService {
  constructor(
    private client: grpc.Client,
    private callCreds?: grpc.CallCredentials,
  ) {}

  async ping(): Promise<PingResponse> {
    return callUnary(this.client, 'ping', {}, this.callCreds);
  }

  async health(): Promise<HealthResponse> {
    return callUnary(this.client, 'health', {}, this.callCreds);
  }

  async getConfig(): Promise<string> {
    const resp = await callUnary<any, any>(this.client, 'getConfig', {}, this.callCreds);
    if (resp?.configYaml) {
      return Buffer.from(resp.configYaml).toString('utf-8');
    }
    return '';
  }

  /** Returns both config YAML and CA cert bytes from GetConfig RPC. */
  async getConfigFull(): Promise<{ configYaml: string; caCert: Buffer | null }> {
    const resp = await callUnary<any, any>(this.client, 'getConfig', {}, this.callCreds);
    return {
      configYaml: resp?.configYaml ? Buffer.from(resp.configYaml).toString('utf-8') : '',
      caCert: resp?.caCert ? Buffer.from(resp.caCert) : null,
    };
  }
}
