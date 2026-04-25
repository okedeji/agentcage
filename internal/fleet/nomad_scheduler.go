package fleet

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/okedeji/agentcage/internal/cage"
)

// NomadSchedulerConfig holds the connection details for a Nomad cluster.
type NomadSchedulerConfig struct {
	Address  string
	Token    string      // ACL token, empty for dev mode
	TLS      *tls.Config // nil for plaintext (embedded dev)
}

func (c NomadSchedulerConfig) String() string {
	tok := ""
	if c.Token != "" {
		tok = "REDACTED"
	}
	return fmt.Sprintf("NomadSchedulerConfig{address=%s, token=%s}", c.Address, tok)
}

func (c NomadSchedulerConfig) GoString() string { return c.String() }

func (c NomadSchedulerConfig) MarshalJSON() ([]byte, error) {
	tok := ""
	if c.Token != "" {
		tok = "REDACTED"
	}
	return json.Marshal(struct {
		Address string `json:"address"`
		Token   string `json:"token"`
		TLS     bool   `json:"tls"`
	}{Address: c.Address, Token: tok, TLS: c.TLS != nil})
}

// NomadScheduler places cage workloads via the Nomad HTTP API. It
// submits a parameterized job per cage VM and lets Nomad handle
// placement, health checking, and rescheduling. The PoolManager is
// still the source of truth for slot accounting.
type NomadScheduler struct {
	pool    *PoolManager
	addr    string
	token   string
	client  *http.Client
	mu      sync.Mutex
	allocs  map[string]*nomadAlloc
	ipSeq   uint32
}

type nomadAlloc struct {
	vmID   string
	hostID string
	jobID  string
}

func NewNomadScheduler(pool *PoolManager, cfg NomadSchedulerConfig) *NomadScheduler {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if cfg.TLS != nil {
		transport.TLSClientConfig = cfg.TLS
	}
	return &NomadScheduler{
		pool:   pool,
		addr:   cfg.Address,
		token:  cfg.Token,
		client: &http.Client{Timeout: 30 * time.Second, Transport: transport},
		allocs: make(map[string]*nomadAlloc),
	}
}

func (s *NomadScheduler) Schedule(ctx context.Context, config cage.VMConfig) (*cage.VMHandle, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	host, err := s.pool.GetAvailableHost()
	if err != nil {
		return nil, fmt.Errorf("scheduling cage %s: %w", config.CageID, err)
	}

	if err := s.pool.AllocateCageSlot(host.ID); err != nil {
		return nil, fmt.Errorf("scheduling cage %s: allocating slot on host %s: %w", config.CageID, host.ID, err)
	}

	jobID := fmt.Sprintf("cage-%s", config.CageID)
	job := s.buildJob(jobID, config, host)

	if err := s.submitJob(ctx, job); err != nil {
		_ = s.pool.ReleaseCageSlot(host.ID)
		return nil, fmt.Errorf("submitting nomad job for cage %s: %w", config.CageID, err)
	}

	vmID := jobID
	s.allocs[vmID] = &nomadAlloc{
		vmID:   vmID,
		hostID: host.ID,
		jobID:  jobID,
	}

	s.ipSeq++
	if s.ipSeq > 255*254 {
		s.ipSeq = 1
	}
	octet3 := (s.ipSeq / 254) % 256
	octet4 := (s.ipSeq % 254) + 1

	return &cage.VMHandle{
		ID:        vmID,
		CageID:    config.CageID,
		IPAddress: fmt.Sprintf("10.0.%d.%d", octet3, octet4),
		StartedAt: time.Now(),
	}, nil
}

func (s *NomadScheduler) Deallocate(ctx context.Context, vmID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	alloc, ok := s.allocs[vmID]
	if !ok {
		return fmt.Errorf("deallocating VM %s: %w", vmID, ErrAllocationNotFound)
	}

	if err := s.stopJob(ctx, alloc.jobID); err != nil {
		return fmt.Errorf("stopping nomad job %s: %w", alloc.jobID, err)
	}

	if err := s.pool.ReleaseCageSlot(alloc.hostID); err != nil {
		return fmt.Errorf("deallocating VM %s: releasing slot on host %s: %w", vmID, alloc.hostID, err)
	}

	delete(s.allocs, vmID)
	return nil
}

func (s *NomadScheduler) Status(ctx context.Context, vmID string) (cage.VMStatus, error) {
	s.mu.Lock()
	alloc, ok := s.allocs[vmID]
	s.mu.Unlock()

	if !ok {
		return cage.VMStatusStopped, fmt.Errorf("VM %s: %w", vmID, ErrAllocationNotFound)
	}

	status, err := s.jobStatus(ctx, alloc.jobID)
	if err != nil {
		return cage.VMStatusRunning, nil
	}

	switch status {
	case "running":
		return cage.VMStatusRunning, nil
	case "dead", "complete":
		return cage.VMStatusStopped, nil
	default:
		return cage.VMStatusRunning, nil
	}
}

// buildJob creates a minimal Nomad job spec for a Firecracker cage.
// The task runs on the host via raw_exec so it has access to /dev/kvm.
func (s *NomadScheduler) buildJob(jobID string, config cage.VMConfig, host *Host) map[string]any {
	return map[string]any{
		"Job": map[string]any{
			"ID":          jobID,
			"Name":        jobID,
			"Type":        "batch",
			"Datacenters": []string{"dc1"},
			"Constraints": []map[string]any{
				{
					"LTarget": "${node.unique.name}",
					"RTarget": host.ID,
					"Operand": "=",
				},
			},
			"TaskGroups": []map[string]any{
				{
					"Name":  "cage",
					"Count": 1,
					"Tasks": []map[string]any{
						{
							"Name":   "firecracker",
							"Driver": "raw_exec",
							"Config": map[string]any{
								"command": "/usr/local/bin/agentcage",
								"args":    []string{"cage-run", "--cage-id", config.CageID},
							},
							"Resources": map[string]any{
								"CPU":      config.VCPUs * 1000,
								"MemoryMB": config.MemoryMB,
							},
						},
					},
				},
			},
		},
	}
}

func (s *NomadScheduler) setAuthHeader(req *http.Request) {
	if s.token != "" {
		req.Header.Set("X-Nomad-Token", s.token)
	}
}

func (s *NomadScheduler) submitJob(ctx context.Context, job map[string]any) error {
	body, err := json.Marshal(job)
	if err != nil {
		return fmt.Errorf("marshaling job: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, s.addr+"/v1/jobs", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	s.setAuthHeader(req)

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("submitting job: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 400 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("nomad returned %d: %s", resp.StatusCode, string(respBody))
	}
	return nil
}

func (s *NomadScheduler) stopJob(ctx context.Context, jobID string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, s.addr+"/v1/job/"+jobID, nil)
	if err != nil {
		return err
	}
	s.setAuthHeader(req)

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("stopping job %s: %w", jobID, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 400 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("nomad returned %d: %s", resp.StatusCode, string(respBody))
	}
	return nil
}

func (s *NomadScheduler) jobStatus(ctx context.Context, jobID string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.addr+"/v1/job/"+jobID, nil)
	if err != nil {
		return "", err
	}
	s.setAuthHeader(req)

	resp, err := s.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("checking job %s: %w", jobID, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 400 {
		return "dead", nil
	}

	var result struct {
		Status string `json:"Status"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("decoding job status: %w", err)
	}
	return result.Status, nil
}
