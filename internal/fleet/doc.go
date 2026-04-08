// Package fleet manages the pool of hosts that run cages: which
// hosts are active, which are warm, which are draining, and how many
// cage slots each one has free. The autoscaler watches the demand
// ledger and the warm pool target, provisions hosts when demand
// rises, and drains them when it falls. Emergency provisioning kicks
// in when fleet utilization passes 90% so cage creation never fails
// for capacity reasons.
//
// Provisioner backends are pluggable. The webhook provisioner POSTs
// to an external service that owns the actual cloud SDK calls; the
// local provisioner is the dev fallback that returns a single static
// host. CagePoolAdapter bridges PoolManager to cage.FleetPool so the
// cage activity layer can allocate slots without importing fleet.
package fleet
