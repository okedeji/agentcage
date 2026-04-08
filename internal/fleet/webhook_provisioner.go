package fleet

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/go-logr/logr"
)

// WebhookProvisioner implements HostProvisioner by calling an external
// webhook service. Keeps agentcage free of cloud provider SDKs: the
// operator deploys a small webhook server (Lambda, Cloud Function, or
// custom service) that translates provision/drain requests into cloud
// API calls. Reference implementations for AWS ASG, Azure VMSS, and
// GCP MIG live in deploy/extensions/.
type WebhookProvisioner struct {
	endpoint   string
	apiKey     string
	httpClient *http.Client
	log        logr.Logger
}

type webhookProvisionRequest struct{}

type webhookProvisionResponse struct {
	HostID    string `json:"host_id"`
	Address   string `json:"address"`
	VCPUs     int32  `json:"vcpus"`
	MemoryMB  int32  `json:"memory_mb"`
	CageSlots int32  `json:"cage_slots"`
}

type webhookDrainRequest struct {
	HostID string `json:"host_id"`
}

type webhookStatusRequest struct {
	HostID string `json:"host_id"`
}

type webhookStatusResponse struct {
	HostID string `json:"host_id"`
	Ready  bool   `json:"ready"`
}

func NewWebhookProvisioner(endpoint, apiKey string, timeout time.Duration, log logr.Logger) *WebhookProvisioner {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	return &WebhookProvisioner{
		endpoint: endpoint,
		apiKey:   apiKey,
		httpClient: &http.Client{
			Timeout: timeout,
		},
		log: log.WithValues("component", "webhook-provisioner"),
	}
}

func (p *WebhookProvisioner) Provision(ctx context.Context) (*Host, error) {
	body, err := json.Marshal(webhookProvisionRequest{})
	if err != nil {
		return nil, fmt.Errorf("marshaling provision request: %w", err)
	}

	resp, err := p.doRequest(ctx, "/provision", body)
	if err != nil {
		return nil, fmt.Errorf("calling provision webhook: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("provision webhook returned HTTP %d", resp.StatusCode)
	}

	var result webhookProvisionResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decoding provision response: %w", err)
	}

	if result.HostID == "" {
		return nil, fmt.Errorf("provision webhook returned empty host_id")
	}

	host := &Host{
		ID:             result.HostID,
		Pool:           PoolProvisioning,
		State:          HostInitializing,
		VCPUsTotal:     result.VCPUs,
		MemoryMBTotal:  result.MemoryMB,
		CageSlotsTotal: result.CageSlots,
	}

	p.log.Info("host provisioned via webhook", "host_id", result.HostID, "address", result.Address, "vcpus", result.VCPUs, "memory_mb", result.MemoryMB)
	return host, nil
}

func (p *WebhookProvisioner) Drain(ctx context.Context, hostID string) error {
	body, err := json.Marshal(webhookDrainRequest{HostID: hostID})
	if err != nil {
		return fmt.Errorf("marshaling drain request: %w", err)
	}

	resp, err := p.doRequest(ctx, "/drain", body)
	if err != nil {
		return fmt.Errorf("calling drain webhook for host %s: %w", hostID, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("drain webhook returned HTTP %d for host %s", resp.StatusCode, hostID)
	}

	p.log.Info("host drained via webhook", "host_id", hostID)
	return nil
}

func (p *WebhookProvisioner) Terminate(ctx context.Context, hostID string) error {
	body, err := json.Marshal(webhookDrainRequest{HostID: hostID})
	if err != nil {
		return fmt.Errorf("marshaling terminate request: %w", err)
	}

	resp, err := p.doRequest(ctx, "/terminate", body)
	if err != nil {
		return fmt.Errorf("calling terminate webhook for host %s: %w", hostID, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("terminate webhook returned HTTP %d for host %s", resp.StatusCode, hostID)
	}

	p.log.Info("host terminated via webhook", "host_id", hostID)
	return nil
}

func (p *WebhookProvisioner) doRequest(ctx context.Context, path string, body []byte) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.endpoint+path, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("building request for %s: %w", path, err)
	}
	req.Header.Set("Content-Type", "application/json")
	if p.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+p.apiKey)
	}
	return p.httpClient.Do(req)
}

// CheckReady polls the webhook for a host's readiness. Returns true when
// the bare metal instance has booted and passed health checks.
func (p *WebhookProvisioner) CheckReady(ctx context.Context, hostID string) (bool, error) {
	body, err := json.Marshal(webhookStatusRequest{HostID: hostID})
	if err != nil {
		return false, fmt.Errorf("marshaling status request: %w", err)
	}

	resp, err := p.doRequest(ctx, "/status", body)
	if err != nil {
		return false, fmt.Errorf("calling status webhook for host %s: %w", hostID, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("status webhook returned HTTP %d for host %s", resp.StatusCode, hostID)
	}

	var result webhookStatusResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return false, fmt.Errorf("decoding status response for host %s: %w", hostID, err)
	}

	return result.Ready, nil
}
