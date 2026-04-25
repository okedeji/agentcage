import { HostPool } from './enums';

export interface PoolStatus {
  pool: HostPool;
  hostCount: number;
  cageSlotsTotal: number;
  cageSlotsUsed: number;
}

export interface FleetStatus {
  totalHosts: number;
  pools: PoolStatus[];
  utilizationRatio: number;
}

export interface HostInfo {
  id: string;
  pool: HostPool;
  state: string;
  cageSlotsTotal: number;
  cageSlotsUsed: number;
  vcpusTotal: number;
  memoryMbTotal: number;
}

export interface ListHostsRequest {
  poolFilter?: HostPool;
}

export interface DrainHostRequest {
  hostId: string;
  reason: string;
  force?: boolean;
}

export interface Capacity {
  pools: PoolStatus[];
  availableCageSlots: number;
}
