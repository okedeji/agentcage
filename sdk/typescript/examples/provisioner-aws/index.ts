/**
 * Reference fleet provisioner using AWS EC2.
 *
 * Usage:
 *   FLEET_AUTH_TOKEN=secret AWS_REGION=us-east-1 npx ts-node index.ts
 *
 * Then configure agentcage:
 *   fleet:
 *     provisioner:
 *       webhook_url: http://localhost:8081
 *
 * Requires: aws-sdk v3 (npm install @aws-sdk/client-ec2)
 * The EC2 instances use a pre-baked AMI with agentcage, Firecracker,
 * kernel, and rootfs already installed.
 */

import { createProvisionerServer, ProvisionResult, StatusResult } from '@agentcage/sdk';

const AUTH_TOKEN = process.env.FLEET_AUTH_TOKEN ?? 'dev-token';
const PORT = parseInt(process.env.PORT ?? '8081', 10);
const AMI_ID = process.env.AGENTCAGE_AMI_ID ?? '';
const INSTANCE_TYPE = process.env.INSTANCE_TYPE ?? 'm6i.metal';
const SUBNET_ID = process.env.SUBNET_ID ?? '';
const SECURITY_GROUP_ID = process.env.SECURITY_GROUP_ID ?? '';
const VCPUS = parseInt(process.env.HOST_VCPUS ?? '128', 10);
const MEMORY_MB = parseInt(process.env.HOST_MEMORY_MB ?? '524288', 10);
const CAGE_SLOTS = parseInt(process.env.HOST_CAGE_SLOTS ?? '50', 10);

// Lazy import so the example compiles without aws-sdk installed.
let ec2: any = null;
async function getEC2() {
  if (!ec2) {
    const { EC2Client } = await import('@aws-sdk/client-ec2');
    ec2 = new EC2Client({ region: process.env.AWS_REGION ?? 'us-east-1' });
  }
  return ec2;
}

const server = createProvisionerServer({
  async provision(): Promise<ProvisionResult> {
    const client = await getEC2();
    const { RunInstancesCommand } = await import('@aws-sdk/client-ec2');

    const result = await client.send(new RunInstancesCommand({
      ImageId: AMI_ID,
      InstanceType: INSTANCE_TYPE,
      MinCount: 1,
      MaxCount: 1,
      SubnetId: SUBNET_ID || undefined,
      SecurityGroupIds: SECURITY_GROUP_ID ? [SECURITY_GROUP_ID] : undefined,
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
    console.log(`Draining host ${hostId} — new cages will not be scheduled`);
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
