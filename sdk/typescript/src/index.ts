// Client — everything the CLI does, as typed async methods.
export { AgentCage, type AgentCageConfig, type ApiKeyAuth } from './client';
export type { VaultConfig, RunConfig, RunEvent, ApiKeyInfo, PackOptions, PackResult } from './client';

// Agent SDK — for TypeScript agents running inside cages.
export { AgentSDK, type AgentConfig } from './agent';

// Judge server — HTTP framework for payload safety classification.
export { createJudgeServer, type EvaluateFn, type JudgeServerConfig } from './judge';

// Provisioner server — HTTP framework for bare-metal host management.
export { createProvisionerServer, type ProvisionerHandler, type ProvisionerServerConfig } from './provisioner';

// Vault client — direct Vault HTTP API access for secret management.
export { VaultClient } from './client/vault';

// Access client — API key management via Vault.
export { AccessClient } from './client/access';

// Shared types.
export * from './types/enums';
export type { AssessmentInfo, AssessmentConfig, Report, CreateAssessmentRequest, ListAssessmentsRequest } from './types/assessment';
export type { Finding, Evidence, ValidationProof, ListFindingsRequest } from './types/findings';
export type { Intervention, ListInterventionsRequest, ResolveCageRequest, ResolveProofGapRequest, ResolveReviewRequest } from './types/intervention';
export type { FleetStatus, HostInfo, Capacity, DrainHostRequest } from './types/fleet';
export type { CageInfo, CageLogs } from './types/cage';
export type { AuditEntry, AuditDigest, ChainStatus, VerifyResult } from './types/audit';
export type { AgentFinding, Directive, DirectiveInstruction, HoldRequest, HoldResponse } from './types/agent';
export type { JudgePayload, JudgeResult } from './types/judge';
export type { ProvisionResult, StatusResult } from './types/provisioner';
