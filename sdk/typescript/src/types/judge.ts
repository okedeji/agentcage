export interface JudgePayload {
  cageType: string;
  vulnClass: string;
  assessmentId: string;
  method: string;
  url: string;
  body: string;
}

export interface JudgeResult {
  safe: boolean;
  confidence: number;
  reason: string;
}

export interface JudgeRequest {
  payloads: JudgePayload[];
}

export interface JudgeResponse {
  results: JudgeResult[];
}
