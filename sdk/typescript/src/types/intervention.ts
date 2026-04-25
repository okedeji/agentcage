import {
  InterventionType,
  InterventionStatus,
  InterventionAction,
  ReviewDecision,
  ProofGapAction,
} from './enums';

export interface Intervention {
  id: string;
  type: InterventionType;
  status: InterventionStatus;
  priority: number;
  cageId?: string;
  assessmentId: string;
  description: string;
  contextData?: Record<string, unknown>;
  timeout: string;
  createdAt: Date;
  resolvedAt?: Date;
}

export interface ListInterventionsRequest {
  statusFilter?: InterventionStatus;
  typeFilter?: InterventionType;
  assessmentIdFilter?: string;
  pageSize?: number;
  pageToken?: string;
}

export interface ResolveCageRequest {
  interventionId: string;
  action: InterventionAction;
  rationale?: string;
  adjustments?: Record<string, string>;
}

export interface ResolveProofGapRequest {
  interventionId: string;
  action: ProofGapAction;
  rationale?: string;
}

export interface FindingAdjustment {
  findingId: string;
  newSeverity?: string;
  notes?: string;
}

export interface ResolveReviewRequest {
  interventionId: string;
  decision: ReviewDecision;
  rationale?: string;
  adjustments?: FindingAdjustment[];
}
