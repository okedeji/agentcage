import type { ProvisionResult, StatusResult } from '../types/provisioner';

export function validateProvisionResult(result: ProvisionResult): void {
  if (!result.hostId || typeof result.hostId !== 'string') {
    throw new Error('provision result: hostId must be a non-empty string');
  }
  if (!result.address || typeof result.address !== 'string') {
    throw new Error('provision result: address must be a non-empty string');
  }
  if (typeof result.vcpus !== 'number' || result.vcpus <= 0) {
    throw new Error('provision result: vcpus must be a positive number');
  }
  if (typeof result.memoryMb !== 'number' || result.memoryMb <= 0) {
    throw new Error('provision result: memoryMb must be a positive number');
  }
  if (typeof result.cageSlots !== 'number' || result.cageSlots <= 0) {
    throw new Error('provision result: cageSlots must be a positive number');
  }
}

export function validateStatusResult(result: StatusResult): void {
  if (!result.hostId || typeof result.hostId !== 'string') {
    throw new Error('status result: hostId must be a non-empty string');
  }
  if (typeof result.ready !== 'boolean') {
    throw new Error('status result: ready must be a boolean');
  }
}

export function parseHostId(body: any): string {
  if (!body || !body.host_id || typeof body.host_id !== 'string') {
    throw new Error('request must contain a non-empty "host_id" string');
  }
  return body.host_id;
}
