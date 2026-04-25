import * as grpc from '@grpc/grpc-js';
import { callUnary } from './client';
import type { Finding, ListFindingsRequest, DeleteByAssessmentResponse } from '../types/findings';

export class FindingsService {
  constructor(
    private client: grpc.Client,
    private callCreds?: grpc.CallCredentials,
  ) {}

  async list(req: ListFindingsRequest): Promise<Finding[]> {
    const resp = await callUnary<any, any>(this.client, 'listFindings', req, this.callCreds);
    return resp.findings ?? [];
  }

  async get(findingId: string): Promise<Finding> {
    const resp = await callUnary<any, any>(this.client, 'getFinding', { findingId }, this.callCreds);
    return resp.finding;
  }

  async delete(findingId: string): Promise<void> {
    await callUnary(this.client, 'deleteFinding', { findingId }, this.callCreds);
  }

  async deleteByAssessment(assessmentId: string): Promise<DeleteByAssessmentResponse> {
    return callUnary(this.client, 'deleteByAssessment', { assessmentId }, this.callCreds);
  }
}
