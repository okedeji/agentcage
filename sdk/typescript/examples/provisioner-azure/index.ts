/**
 * Reference fleet provisioner using Azure VMs.
 *
 * Usage:
 *   FLEET_AUTH_TOKEN=secret AZURE_SUBSCRIPTION_ID=... AZURE_RESOURCE_GROUP=... npx ts-node index.ts
 *
 * Then configure agentcage:
 *   fleet:
 *     provisioner:
 *       webhook_url: http://localhost:8081
 *
 * Requires: @azure/arm-compute @azure/identity (npm install @azure/arm-compute @azure/identity)
 */

import { createProvisionerServer, ProvisionResult, StatusResult } from '@agentcage/sdk';

const AUTH_TOKEN = process.env.FLEET_AUTH_TOKEN ?? 'dev-token';
const PORT = parseInt(process.env.PORT ?? '8081', 10);
const SUBSCRIPTION_ID = process.env.AZURE_SUBSCRIPTION_ID ?? '';
const RESOURCE_GROUP = process.env.AZURE_RESOURCE_GROUP ?? '';
const LOCATION = process.env.AZURE_LOCATION ?? 'eastus';
const VM_SIZE = process.env.VM_SIZE ?? 'Standard_D96s_v5';
const IMAGE_ID = process.env.AGENTCAGE_IMAGE_ID ?? '';
const SUBNET_ID = process.env.SUBNET_ID ?? '';
const VCPUS = parseInt(process.env.HOST_VCPUS ?? '96', 10);
const MEMORY_MB = parseInt(process.env.HOST_MEMORY_MB ?? '393216', 10);
const CAGE_SLOTS = parseInt(process.env.HOST_CAGE_SLOTS ?? '40', 10);

let computeClient: any = null;
let networkClient: any = null;

async function getClients() {
  if (!computeClient) {
    const { DefaultAzureCredential } = await import('@azure/identity');
    const { ComputeManagementClient } = await import('@azure/arm-compute');
    const { NetworkManagementClient } = await import('@azure/arm-network');
    const cred = new DefaultAzureCredential();
    computeClient = new ComputeManagementClient(cred, SUBSCRIPTION_ID);
    networkClient = new NetworkManagementClient(cred, SUBSCRIPTION_ID);
  }
  return { compute: computeClient, network: networkClient };
}

let counter = 0;

const server = createProvisionerServer({
  async provision(): Promise<ProvisionResult> {
    const { compute, network } = await getClients();
    const name = `agentcage-host-${Date.now()}-${++counter}`;

    // Create NIC
    const nicResult = await network.networkInterfaces.beginCreateOrUpdateAndWait(
      RESOURCE_GROUP, `${name}-nic`, {
        location: LOCATION,
        ipConfigurations: [{
          name: 'primary',
          subnet: { id: SUBNET_ID },
          privateIPAllocationMethod: 'Dynamic',
        }],
      },
    );

    // Create VM
    await compute.virtualMachines.beginCreateOrUpdateAndWait(
      RESOURCE_GROUP, name, {
        location: LOCATION,
        hardwareProfile: { vmSize: VM_SIZE },
        storageProfile: {
          imageReference: { id: IMAGE_ID },
          osDisk: { createOption: 'FromImage', managedDisk: { storageAccountType: 'Premium_LRS' } },
        },
        networkProfile: {
          networkInterfaces: [{ id: nicResult.id }],
        },
        osProfile: {
          computerName: name,
          adminUsername: 'azureuser',
          linuxConfiguration: { disablePasswordAuthentication: true },
        },
        tags: { Service: 'agentcage' },
      },
    );

    const ip = nicResult.ipConfigurations?.[0]?.privateIPAddress ?? '';

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
    const { compute } = await getClients();
    await compute.virtualMachines.beginDeleteAndWait(RESOURCE_GROUP, hostId);
    console.log(`Terminated host ${hostId}`);
  },

  async status(hostId: string): Promise<StatusResult> {
    const { compute } = await getClients();
    const vm = await compute.virtualMachines.get(RESOURCE_GROUP, hostId, { expand: 'instanceView' });
    const powerState = vm.instanceView?.statuses?.find(
      (s: any) => s.code?.startsWith('PowerState/'),
    )?.code;
    return { hostId, ready: powerState === 'PowerState/running' };
  },
}, { port: PORT, authToken: AUTH_TOKEN });

server.listen(PORT, () => {
  console.log(`Fleet provisioner (Azure) listening on :${PORT}`);
});
