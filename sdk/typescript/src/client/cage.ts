import * as grpc from '@grpc/grpc-js';
import { callUnary } from './client';
import type { CageLogs, GetCageLogsRequest } from '../types/cage';

export class CageService {
  constructor(
    private client: grpc.Client,
    private callCreds?: grpc.CallCredentials,
  ) {}

  async listByAssessment(assessmentId: string): Promise<string[]> {
    const resp = await callUnary<any, any>(this.client, 'listCagesByAssessment', { assessmentId }, this.callCreds);
    return resp.cageIds ?? [];
  }

  async getLogs(req: GetCageLogsRequest): Promise<CageLogs> {
    return callUnary(this.client, 'getCageLogs', req, this.callCreds);
  }

  /** Stream cage logs via polling. Yields new lines as they appear.
   *  Stops when the cage completes or the caller breaks. */
  async *streamLogs(cageId: string, pollIntervalMs = 1000): AsyncGenerator<string> {
    let seen = 0;

    while (true) {
      const resp = await this.getLogs({ cageId, tailLines: 0 });
      const lines = resp.lines ?? [];

      // Yield only lines we haven't seen yet.
      for (let i = seen; i < lines.length; i++) {
        yield lines[i];
      }
      seen = lines.length;

      if (!resp.isRunning) {
        return;
      }

      await new Promise((resolve) => setTimeout(resolve, pollIntervalMs));
    }
  }
}
