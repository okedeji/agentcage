import * as grpc from '@grpc/grpc-js';
import { callUnary } from './client';
import type {
  Intervention,
  ListInterventionsRequest,
  ResolveCageRequest,
  ResolveProofGapRequest,
  ResolveReviewRequest,
} from '../types/intervention';

export class InterventionService {
  constructor(
    private client: grpc.Client,
    private callCreds?: grpc.CallCredentials,
  ) {}

  async list(req: ListInterventionsRequest = {}): Promise<{ interventions: Intervention[]; nextPageToken?: string }> {
    return callUnary(this.client, 'listInterventions', req, this.callCreds);
  }

  async get(interventionId: string): Promise<Intervention> {
    const resp = await callUnary<any, any>(this.client, 'getIntervention', { interventionId }, this.callCreds);
    return resp.intervention;
  }

  async resolveCage(req: ResolveCageRequest): Promise<void> {
    await callUnary(this.client, 'resolveCageIntervention', req, this.callCreds);
  }

  async resolveProofGap(req: ResolveProofGapRequest): Promise<void> {
    await callUnary(this.client, 'resolveProofGap', req, this.callCreds);
  }

  async resolveReview(req: ResolveReviewRequest): Promise<void> {
    await callUnary(this.client, 'resolveAssessmentReview', req, this.callCreds);
  }
}
