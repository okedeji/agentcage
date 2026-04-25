import * as grpc from '@grpc/grpc-js';
import { callUnary } from './client';
import type { FleetStatus, HostInfo, ListHostsRequest, DrainHostRequest, Capacity } from '../types/fleet';

export class FleetService {
  constructor(
    private client: grpc.Client,
    private callCreds?: grpc.CallCredentials,
  ) {}

  async status(): Promise<FleetStatus> {
    return callUnary(this.client, 'getFleetStatus', {}, this.callCreds);
  }

  async listHosts(req: ListHostsRequest = {}): Promise<HostInfo[]> {
    const resp = await callUnary<any, any>(this.client, 'listHosts', req, this.callCreds);
    return resp.hosts ?? [];
  }

  async drain(req: DrainHostRequest): Promise<void> {
    await callUnary(this.client, 'drainHost', req, this.callCreds);
  }

  async capacity(): Promise<Capacity> {
    return callUnary(this.client, 'getCapacity', {}, this.callCreds);
  }
}
