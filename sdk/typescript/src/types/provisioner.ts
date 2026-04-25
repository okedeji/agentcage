export interface ProvisionResult {
  hostId: string;
  address: string;
  vcpus: number;
  memoryMb: number;
  cageSlots: number;
}

export interface DrainRequest {
  hostId: string;
}

export interface TerminateRequest {
  hostId: string;
}

export interface StatusRequest {
  hostId: string;
}

export interface StatusResult {
  hostId: string;
  ready: boolean;
}
