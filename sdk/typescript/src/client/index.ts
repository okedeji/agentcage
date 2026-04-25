import { AgentCageConfig, getServiceClient, createCallCredentials } from './client';
import { AssessmentService } from './assessment';
import { FindingsService } from './findings';
import { InterventionService } from './intervention';
import { FleetService } from './fleet';
import { CageService } from './cage';
import { ControlService } from './control';
import { AuditService } from './audit';
import { VaultClient, VaultConfig } from './vault';
import { AccessClient } from './access';
import { run, follow, RunConfig, RunEvent } from './run';
import { pack, PackOptions, PackResult } from './pack';
import type { AssessmentInfo } from '../types/assessment';
import type { PingResponse } from '../types/control';
import * as yaml from 'js-yaml';
import * as grpc from '@grpc/grpc-js';

export type { AgentCageConfig, ApiKeyAuth, MtlsAuth } from './client';
export type { VaultConfig } from './vault';
export type { RunConfig, RunEvent } from './run';
export type { PackOptions, PackResult, BundleManifest } from './pack';
export type { ApiKeyInfo } from './access';

export class AgentCage {
  readonly assessment: AssessmentService;
  readonly findings: FindingsService;
  readonly intervention: InterventionService;
  readonly fleet: FleetService;
  readonly cage: CageService;
  readonly control: ControlService;
  readonly audit: AuditService;

  /** Raw YAML config string from the orchestrator. Set after connect(). */
  configYaml = '';

  /** Parsed operator config. Set after connect(). */
  config: Record<string, any> = {};

  private clients: grpc.Client[] = [];

  constructor(config: AgentCageConfig) {
    const callCreds = config.auth?.type === 'apiKey'
      ? createCallCredentials(config.auth)
      : undefined;

    const mkClient = (proto: string, pkg: string, svc: string) => {
      const c = getServiceClient(proto, pkg, svc, config);
      this.clients.push(c);
      return c;
    };

    this.assessment = new AssessmentService(
      mkClient('assessment.proto', 'agentcage.assessment.v1', 'AssessmentService'), callCreds);
    this.findings = new FindingsService(
      mkClient('findings.proto', 'agentcage.findings.v1', 'FindingsService'), callCreds);
    this.intervention = new InterventionService(
      mkClient('intervention.proto', 'agentcage.intervention.v1', 'InterventionService'), callCreds);
    this.fleet = new FleetService(
      mkClient('fleet.proto', 'agentcage.fleet.v1', 'FleetService'), callCreds);
    this.cage = new CageService(
      mkClient('cage.proto', 'agentcage.cage.v1', 'CageService'), callCreds);
    this.control = new ControlService(
      mkClient('control.proto', 'agentcage.control.v1', 'ControlService'), callCreds);
    this.audit = new AuditService(
      mkClient('audit.proto', 'agentcage.audit.v1', 'AuditService'), callCreds);
  }

  /** Verify connectivity and fetch operator config.
   *  Equivalent to `agentcage connect`. Stores the config for use by run(). */
  async connect(): Promise<{ ping: PingResponse; config: Record<string, any> }> {
    const ping = await this.control.ping();
    this.configYaml = await this.control.getConfig();
    if (this.configYaml) {
      this.config = (yaml.load(this.configYaml) as Record<string, any>) ?? {};
    }
    return { ping, config: this.config };
  }

  /** Get a config value by dotted path.
   *  Equivalent to `agentcage config get <key>`. */
  configGet(path: string): unknown {
    const parts = path.split('.');
    let current: any = this.config;
    for (const part of parts) {
      if (current == null || typeof current !== 'object') return undefined;
      current = current[part];
    }
    return current;
  }

  /** Create an assessment and optionally follow its progress.
   *  Equivalent to `agentcage run`. */
  async run(runConfig: RunConfig): Promise<AssessmentInfo> {
    return run(this.assessment, runConfig);
  }

  /** Stream assessment events as an async iterator. */
  follow(assessmentId: string, pollIntervalMs?: number): AsyncGenerator<RunEvent> {
    return follow(this.assessment, assessmentId, pollIntervalMs);
  }

  /** Create a Vault client for secret management.
   *  Equivalent to `agentcage vault`. */
  vault(vaultConfig: VaultConfig): VaultClient {
    return new VaultClient(vaultConfig);
  }

  /** Create an access client for API key management.
   *  Equivalent to `agentcage access`. */
  access(vaultConfig: VaultConfig): AccessClient {
    return new AccessClient(new VaultClient(vaultConfig));
  }

  /** Bundle an agent directory into a .cage file.
   *  Equivalent to `agentcage pack`. */
  async pack(dir: string, options?: PackOptions): Promise<PackResult> {
    return pack(dir, options);
  }

  close(): void {
    for (const c of this.clients) {
      c.close();
    }
    this.clients = [];
  }
}
