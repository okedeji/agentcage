/**
 * Reference fleet provisioner using GCP Compute Engine.
 *
 * Usage:
 *   FLEET_AUTH_TOKEN=secret ORCHESTRATOR_ADDR=orchestrator:9090 ORCHESTRATOR_API_KEY=ak-xxx \
 *   GCP_PROJECT=my-project GCP_ZONE=us-central1-a npx ts-node index.ts
 *
 * Then configure agentcage:
 *   fleet:
 *     provisioner:
 *       webhook_url: http://localhost:8081
 *
 * Requires: @google-cloud/compute (npm install @google-cloud/compute)
 */

import { createProvisionerServer, generateJoinScript, ProvisionResult, StatusResult } from '@agentcage/sdk';

const AUTH_TOKEN = process.env.FLEET_AUTH_TOKEN ?? 'dev-token';
const PORT = parseInt(process.env.PORT ?? '8081', 10);
const ORCHESTRATOR_ADDR = process.env.ORCHESTRATOR_ADDR ?? '';
const ORCHESTRATOR_API_KEY = process.env.ORCHESTRATOR_API_KEY ?? '';
const PROJECT = process.env.GCP_PROJECT ?? '';
const ZONE = process.env.GCP_ZONE ?? 'us-central1-a';
const MACHINE_TYPE = process.env.MACHINE_TYPE ?? 'n2-standard-96';
const NETWORK = process.env.NETWORK ?? 'default';
const VCPUS = parseInt(process.env.HOST_VCPUS ?? '96', 10);
const MEMORY_MB = parseInt(process.env.HOST_MEMORY_MB ?? '393216', 10);
const CAGE_SLOTS = parseInt(process.env.HOST_CAGE_SLOTS ?? '40', 10);
const ROOTFS_URL = process.env.ROOTFS_URL ?? '';

let computeClient: any = null;
async function getCompute() {
  if (!computeClient) {
    const { InstancesClient } = await import('@google-cloud/compute');
    computeClient = new InstancesClient();
  }
  return computeClient;
}

const joinScript = generateJoinScript({
  orchestratorAddress: ORCHESTRATOR_ADDR,
  apiKey: ORCHESTRATOR_API_KEY,
  rootfsUrl: ROOTFS_URL || undefined,
});

let counter = 0;

const server = createProvisionerServer({
  async provision(): Promise<ProvisionResult> {
    const client = await getCompute();
    const name = `agentcage-host-${Date.now()}-${++counter}`;

    const [operation] = await client.insert({
      project: PROJECT,
      zone: ZONE,
      instanceResource: {
        name,
        machineType: `zones/${ZONE}/machineTypes/${MACHINE_TYPE}`,
        disks: [{
          boot: true,
          autoDelete: true,
          initializeParams: {
            sourceImage: 'projects/ubuntu-os-cloud/global/images/family/ubuntu-2404-lts',
            diskSizeGb: '200',
            diskType: `zones/${ZONE}/diskTypes/pd-ssd`,
          },
        }],
        networkInterfaces: [{ network: `global/networks/${NETWORK}` }],
        metadata: {
          items: [{ key: 'startup-script', value: joinScript }],
        },
        labels: { service: 'agentcage' },
      },
    });
    await operation.promise();

    const [instance] = await client.get({ project: PROJECT, zone: ZONE, instance: name });
    const ip = instance.networkInterfaces?.[0]?.networkIP ?? '';

    return {
      hostId: name,
      address: ip,
      vcpus: VCPUS,
      memoryMb: MEMORY_MB,
      cageSlots: CAGE_SLOTS,
    };
  },

  async drain(hostId: string): Promise<void> {
    console.log(`Draining host ${hostId}`);
  },

  async terminate(hostId: string): Promise<void> {
    const client = await getCompute();
    const [operation] = await client.delete({ project: PROJECT, zone: ZONE, instance: hostId });
    await operation.promise();
    console.log(`Terminated host ${hostId}`);
  },

  async status(hostId: string): Promise<StatusResult> {
    const client = await getCompute();
    const [instance] = await client.get({ project: PROJECT, zone: ZONE, instance: hostId });
    return { hostId, ready: instance.status === 'RUNNING' };
  },
}, { port: PORT, authToken: AUTH_TOKEN });

server.listen(PORT, () => {
  console.log(`Fleet provisioner (GCP) listening on :${PORT}`);
});
