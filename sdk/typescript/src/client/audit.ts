import * as grpc from '@grpc/grpc-js';
import { callUnary } from './client';
import type {
  AuditEntry,
  AuditDigest,
  ChainStatus,
  VerifyResult,
  ListEntriesRequest,
} from '../types/audit';

export class AuditService {
  constructor(
    private client: grpc.Client,
    private callCreds?: grpc.CallCredentials,
  ) {}

  async verify(cageId: string): Promise<VerifyResult> {
    return callUnary(this.client, 'verifyChain', { cageId }, this.callCreds);
  }

  async list(req: ListEntriesRequest): Promise<AuditEntry[]> {
    const resp = await callUnary<any, any>(this.client, 'getEntries', req, this.callCreds);
    return resp.entries ?? [];
  }

  async show(entryId: string): Promise<AuditEntry> {
    const resp = await callUnary<any, any>(this.client, 'getEntry', { entryId }, this.callCreds);
    return resp.entry;
  }

  async export(cageId: string): Promise<Buffer> {
    const resp = await callUnary<any, any>(this.client, 'exportCage', { cageId }, this.callCreds);
    return Buffer.from(resp.exportJson);
  }

  async digest(cageId: string): Promise<AuditDigest> {
    return callUnary(this.client, 'getDigest', { cageId }, this.callCreds);
  }

  async status(cageId: string): Promise<ChainStatus> {
    return callUnary(this.client, 'chainStatus', { cageId }, this.callCreds);
  }

  async keys(cageId: string): Promise<string[]> {
    const resp = await callUnary<any, any>(this.client, 'getKeyVersions', { cageId }, this.callCreds);
    return resp.keyVersions ?? [];
  }

  async listCages(assessmentId: string): Promise<string[]> {
    const resp = await callUnary<any, any>(this.client, 'listCagesWithAudit', { assessmentId }, this.callCreds);
    return resp.cageIds ?? [];
  }
}
