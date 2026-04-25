export interface CageInfo {
  cageId: string;
  assessmentId: string;
  type: string;
  status: string;
  vmId?: string;
  ipAddress?: string;
  startedAt?: Date;
  stoppedAt?: Date;
}

export interface CageLogs {
  cageId: string;
  lines: string[];
  isRunning: boolean;
}

export interface GetCageLogsRequest {
  cageId: string;
  tailLines?: number;
}
