export interface AuditEntry {
  id: string;
  cageId: string;
  assessmentId: string;
  sequence: number;
  type: string;
  timestamp: Date;
  data: Buffer;
  keyVersion: string;
  previousHash: Buffer;
  signature: Buffer;
}

export interface AuditDigest {
  cageId: string;
  assessmentId: string;
  entryCount: number;
  chainHeadHash: Buffer;
  signature: Buffer;
  keyVersion: string;
  createdAt: Date;
}

export interface ChainStatus {
  cageId: string;
  assessmentId: string;
  entryCount: number;
  firstTimestamp?: Date;
  latestTimestamp?: Date;
  hasDigest: boolean;
  keyVersions: string[];
}

export interface VerifyResult {
  valid: boolean;
  error?: string;
  entryCount: number;
}

export interface ListEntriesRequest {
  cageId: string;
  typeFilter?: string;
  limit?: number;
}
