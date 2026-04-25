import * as grpc from '@grpc/grpc-js';
import { callUnary } from './client';
import type {
  AssessmentInfo,
  CreateAssessmentRequest,
  ListAssessmentsRequest,
  Report,
} from '../types/assessment';

export class AssessmentService {
  constructor(
    private client: grpc.Client,
    private callCreds?: grpc.CallCredentials,
  ) {}

  async create(req: CreateAssessmentRequest): Promise<AssessmentInfo> {
    const resp = await callUnary<any, any>(this.client, 'createAssessment', req, this.callCreds);
    return resp.assessment;
  }

  async get(assessmentId: string): Promise<AssessmentInfo> {
    const resp = await callUnary<any, any>(this.client, 'getAssessment', { assessmentId }, this.callCreds);
    return resp.assessment;
  }

  async list(req: ListAssessmentsRequest = {}): Promise<{ assessments: AssessmentInfo[]; nextPageToken?: string }> {
    return callUnary(this.client, 'listAssessments', req, this.callCreds);
  }

  async getReport(assessmentId: string): Promise<Report> {
    const resp = await callUnary<any, any>(this.client, 'getReport', { assessmentId }, this.callCreds);
    return JSON.parse(Buffer.from(resp.reportJson).toString());
  }
}
