export interface PingResponse {
  version: string;
  status: string;
}

export interface HealthResponse {
  services: Record<string, string>;
}
