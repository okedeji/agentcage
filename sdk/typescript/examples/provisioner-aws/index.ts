/**
 * Reference fleet provisioner using AWS EC2.
 *
 * Usage:
 *   FLEET_AUTH_TOKEN=secret ORCHESTRATOR_ADDR=orchestrator:9090 ORCHESTRATOR_API_KEY=ak-xxx npx ts-node index.ts
 *
 * Then configure agentcage:
 *   fleet:
 *     provisioner:
 *       webhook_url: http://localhost:8081
 *
 * Requires: @aws-sdk/client-ec2 (npm install @aws-sdk/client-ec2)
 */

import { createProvisionerServer, generateJoinScript, ProvisionResult, StatusResult } from '@agentcage/sdk';

const AUTH_TOKEN = process.env.FLEET_AUTH_TOKEN ?? 'dev-token';
const PORT = parseInt(process.env.PORT ?? '8081', 10);
const ORCHESTRATOR_ADDR = process.env.ORCHESTRATOR_ADDR ?? '';
const ORCHESTRATOR_API_KEY = process.env.ORCHESTRATOR_API_KEY ?? '';
const INSTANCE_TYPE = process.env.INSTANCE_TYPE ?? 'm6i.metal';
const SUBNET_ID = process.env.SUBNET_ID ?? '';
const SECURITY_GROUP_ID = process.env.SECURITY_GROUP_ID ?? '';
const VCPUS = parseInt(process.env.HOST_VCPUS ?? '128', 10);
const MEMORY_MB = parseInt(process.env.HOST_MEMORY_MB ?? '524288', 10);
const CAGE_SLOTS = parseInt(process.env.HOST_CAGE_SLOTS ?? '50', 10);
const ROOTFS_URL = process.env.ROOTFS_URL ?? '';

let ec2: any = null;
async function getEC2() {
  if (!ec2) {
    const { EC2Client } = await import('@aws-sdk/client-ec2');
    ec2 = new EC2Client({ region: process.env.AWS_REGION ?? 'us-east-1' });
  }
  return ec2;
}

// Generate the join script once — same for every host.
const joinScript = generateJoinScript({
  orchestratorAddress: ORCHESTRATOR_ADDR,
  apiKey: ORCHESTRATOR_API_KEY,
  rootfsUrl: ROOTFS_URL || undefined,
});

const server = createProvisionerServer({
  async provision(): Promise<ProvisionResult> {
    const client = await getEC2();
    const { RunInstancesCommand } = await import('@aws-sdk/client-ec2');

    const result = await client.send(new RunInstancesCommand({
      InstanceType: INSTANCE_TYPE,
      // Base Ubuntu — agentcage join handles all setup.
      ImageId: 'resolve-latest-ubuntu-ami',
      MinCount: 1,
      MaxCount: 1,
      SubnetId: SUBNET_ID || undefined,
      SecurityGroupIds: SECURITY_GROUP_ID ? [SECURITY_GROUP_ID] : undefined,
      UserData: Buffer.from(joinScript).toString('base64'),
      TagSpecifications: [{
        ResourceType: 'instance',
        Tags: [
          { Key: 'Name', Value: 'agentcage-cage-host' },
          { Key: 'Service', Value: 'agentcage' },
        ],
      }],
    }));

    const instance = result.Instances![0];
    return {
      hostId: instance.InstanceId!,
      address: instance.PrivateIpAddress!,
      vcpus: VCPUS,
      memoryMb: MEMORY_MB,
      cageSlots: CAGE_SLOTS,
    };
  },

  async drain(hostId: string): Promise<void> {
    console.log(`Draining host ${hostId}`);
  },

  async terminate(hostId: string): Promise<void> {
    const client = await getEC2();
    const { TerminateInstancesCommand } = await import('@aws-sdk/client-ec2');
    await client.send(new TerminateInstancesCommand({ InstanceIds: [hostId] }));
    console.log(`Terminated host ${hostId}`);
  },

  async status(hostId: string): Promise<StatusResult> {
    const client = await getEC2();
    const { DescribeInstancesCommand } = await import('@aws-sdk/client-ec2');
    const result = await client.send(new DescribeInstancesCommand({ InstanceIds: [hostId] }));
    const state = result.Reservations?.[0]?.Instances?.[0]?.State?.Name;
    return { hostId, ready: state === 'running' };
  },
}, { port: PORT, authToken: AUTH_TOKEN });

server.listen(PORT, () => {
  console.log(`Fleet provisioner (AWS) listening on :${PORT}`);
});
