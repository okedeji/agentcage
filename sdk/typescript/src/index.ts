/**
 * agentcage TypeScript SDK — thin gRPC client for the agentcage platform.
 *
 * Usage:
 *   const client = new AgentCage("localhost:9090");
 *   const assessment = await client.run({ agent: "./solver.cage", target: ["app.example.com"] });
 *   for await (const finding of assessment.findings()) { ... }
 */

export interface RunConfig {
  agent: string;
  target: string[];
  tokenBudget?: number;
  maxDuration?: string;
  compliance?: string;
}

export interface Finding {
  id: string;
  title: string;
  severity: string;
  vulnClass: string;
  endpoint: string;
  status: string;
}

export interface AssessmentStatus {
  id: string;
  status: string;
  totalCages: number;
  findings: number;
}

export interface Intervention {
  id: string;
  type: string;
  status: string;
  cageId: string;
  description: string;
}

export class Assessment {
  readonly id: string;
  private client: AgentCage;

  constructor(id: string, client: AgentCage) {
    this.id = id;
    this.client = client;
  }

  async status(): Promise<AssessmentStatus> {
    // TODO: gRPC call to AssessmentService.GetAssessment
    return { id: this.id, status: "running", totalCages: 0, findings: 0 };
  }

  async *findings(pollInterval = 5000): AsyncGenerator<Finding> {
    // TODO: Poll for new findings until assessment completes
  }

  async wait(pollInterval = 5000): Promise<AssessmentStatus> {
    while (true) {
      const info = await this.status();
      if (info.status === "approved" || info.status === "rejected") {
        return info;
      }
      await new Promise((resolve) => setTimeout(resolve, pollInterval));
    }
  }
}

export class AgentCage {
  private addr: string;

  constructor(addr: string = "localhost:9090") {
    this.addr = addr;
  }

  async run(config: RunConfig): Promise<Assessment> {
    // TODO: gRPC call to AssessmentService.CreateAssessment
    const assessmentId = "pending-grpc-integration";
    return new Assessment(assessmentId, this);
  }

  async test(config: RunConfig): Promise<string> {
    // TODO: gRPC call to CageService.CreateCage
    return "pending-grpc-integration";
  }

  async interventions(): Promise<Intervention[]> {
    // TODO: gRPC call to InterventionService.ListInterventions
    return [];
  }

  async resolve(
    interventionId: string,
    action: "resume" | "kill" | "allow" | "block",
    rationale?: string
  ): Promise<void> {
    // TODO: gRPC call to InterventionService.ResolveCageIntervention
  }

  async fleetStatus(): Promise<{ totalHosts: number }> {
    // TODO: gRPC call to FleetService.GetFleetStatus
    return { totalHosts: 0 };
  }

  close(): void {
    // TODO: Close gRPC channel
  }
}

export default AgentCage;
