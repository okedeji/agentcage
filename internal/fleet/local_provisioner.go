package fleet

import (
	"context"
	"fmt"

	"github.com/go-logr/logr"
)

// LocalHostProvisioner is a no-op HostProvisioner for single-machine mode.
// It cannot provision new hosts (there's only one machine) and draining
// is a no-op. The autoscaler should be configured with MinBuffer=0 so
// Provision is never called in practice.
type LocalHostProvisioner struct {
	log logr.Logger
}

func NewLocalHostProvisioner(log logr.Logger) *LocalHostProvisioner {
	return &LocalHostProvisioner{log: log.WithValues("component", "local-provisioner")}
}

func (p *LocalHostProvisioner) Provision(_ context.Context) (*Host, error) {
	return nil, fmt.Errorf("local mode: cannot provision additional hosts")
}

func (p *LocalHostProvisioner) Drain(_ context.Context, hostID string) error {
	p.log.V(1).Info("drain is a no-op in local mode", "host_id", hostID)
	return nil
}

func (p *LocalHostProvisioner) Terminate(_ context.Context, hostID string) error {
	p.log.V(1).Info("terminate is a no-op in local mode", "host_id", hostID)
	return nil
}

func (p *LocalHostProvisioner) CheckReady(_ context.Context, _ string) (bool, error) {
	return true, nil
}
