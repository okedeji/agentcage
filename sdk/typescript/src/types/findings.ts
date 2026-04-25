import { FindingStatus, Severity } from './enums';

export interface Evidence {
  request?: Buffer;
  response?: Buffer;
  screenshot?: Buffer;
  poc?: string;
  metadata?: Record<string, string>;
}

export interface ValidationProof {
  reproductionSteps: string;
  confirmed: boolean;
  deterministic: boolean;
  validatorCageId: string;
  evidence?: string;
}

export interface Finding {
  id: string;
  assessmentId: string;
  cageId: string;
  status: FindingStatus;
  severity: Severity;
  title: string;
  description?: string;
  vulnClass: string;
  endpoint: string;
  evidence?: Evidence;
  parentFindingId?: string;
  chainDepth?: number;
  cwe?: string;
  cvssScore?: number;
  remediation?: string;
  validationProof?: ValidationProof;
  createdAt?: Date;
  updatedAt?: Date;
  validatedAt?: Date;
}

export interface ListFindingsRequest {
  assessmentId: string;
  statusFilter?: FindingStatus;
  severityFilter?: Severity;
  limit?: number;
}

export interface DeleteByAssessmentResponse {
  deleted: number;
}
