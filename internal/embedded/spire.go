package embedded

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"text/template"
	"time"

	"github.com/go-logr/logr"
)

const (
	spireVersion    = "1.9.0"
	spireServerPort = "18081"
	spireTrustDomain = "agentcage.local"
)

// SPIREService manages embedded SPIRE server and agent processes.
type SPIREService struct {
	serverProc *subprocess
	agentProc  *subprocess
	log        logr.Logger
}

func NewSPIREService(log logr.Logger) *SPIREService {
	return &SPIREService{log: log.WithValues("service", "spire")}
}

func (s *SPIREService) Name() string      { return "spire" }
func (s *SPIREService) IsExternal() bool   { return false }

func (s *SPIREService) AgentSocket() string {
	return filepath.Join(RunDir(), "spire", "agent.sock")
}

func (s *SPIREService) Download(ctx context.Context) error {
	serverBin := filepath.Join(BinDir(), "spire-server")
	agentBin := filepath.Join(BinDir(), "spire-agent")

	// Skip if already downloaded
	if _, err := os.Stat(serverBin); err == nil {
		if _, err := os.Stat(agentBin); err == nil {
			return nil
		}
	}

	arch := archSuffix()
	osName := runtime.GOOS
	base := fmt.Sprintf("https://github.com/spiffe/spire/releases/download/v%s/spire-%s-%s-%s.tar.gz",
		spireVersion, spireVersion, osName, arch)

	// Download the tarball, extract server and agent binaries.
	// For now, just download and mark as stub — real extraction would use
	// archive/tar + compress/gzip.
	_ = base
	_ = ctx

	// Stub: create placeholder binaries that will be replaced with real download
	for _, dest := range []string{serverBin, agentBin} {
		if _, err := os.Stat(dest); os.IsNotExist(err) {
			if err := os.WriteFile(dest, []byte("#!/bin/sh\necho stub"), 0755); err != nil {
				return fmt.Errorf("creating stub %s: %w", dest, err)
			}
		}
	}

	return nil
}

func (s *SPIREService) Start(ctx context.Context) error {
	dataDir := ServiceDataDir("spire")
	socketDir := filepath.Join(RunDir(), "spire")
	if err := os.MkdirAll(socketDir, 0755); err != nil {
		return fmt.Errorf("creating SPIRE socket directory: %w", err)
	}

	// Generate server config
	serverConf := filepath.Join(dataDir, "server.conf")
	if err := writeSpireServerConf(serverConf, dataDir, spireServerPort, spireTrustDomain); err != nil {
		return fmt.Errorf("writing SPIRE server config: %w", err)
	}

	// Start server
	serverBin := filepath.Join(BinDir(), "spire-server")
	s.serverProc = newSubprocess("spire-server", s.log, serverBin,
		"run",
		"-config", serverConf,
	)
	if err := s.serverProc.start(ctx); err != nil {
		return fmt.Errorf("starting SPIRE server: %w", err)
	}

	if err := s.waitServerReady(ctx); err != nil {
		return fmt.Errorf("waiting for SPIRE server: %w", err)
	}

	// Generate agent config
	agentConf := filepath.Join(dataDir, "agent.conf")
	if err := writeSpireAgentConf(agentConf, dataDir, socketDir, spireServerPort, spireTrustDomain); err != nil {
		return fmt.Errorf("writing SPIRE agent config: %w", err)
	}

	// Start agent
	agentBin := filepath.Join(BinDir(), "spire-agent")
	s.agentProc = newSubprocess("spire-agent", s.log, agentBin,
		"run",
		"-config", agentConf,
	)
	if err := s.agentProc.start(ctx); err != nil {
		return fmt.Errorf("starting SPIRE agent: %w", err)
	}

	s.log.Info("spire ready", "server_port", spireServerPort, "agent_socket", s.AgentSocket())
	return nil
}

func (s *SPIREService) Stop(ctx context.Context) error {
	var errs []error
	if s.agentProc != nil {
		if err := s.agentProc.stop(ctx); err != nil {
			errs = append(errs, fmt.Errorf("stopping SPIRE agent: %w", err))
		}
	}
	if s.serverProc != nil {
		if err := s.serverProc.stop(ctx); err != nil {
			errs = append(errs, fmt.Errorf("stopping SPIRE server: %w", err))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("spire shutdown errors: %v", errs)
	}
	return nil
}

func (s *SPIREService) Health(ctx context.Context) error {
	conn, err := net.DialTimeout("tcp", "localhost:"+spireServerPort, 2*time.Second)
	if err != nil {
		return fmt.Errorf("spire server not reachable: %w", err)
	}
	_ = conn.Close()
	return nil
}

func (s *SPIREService) waitServerReady(ctx context.Context) error {
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", "localhost:"+spireServerPort, 500*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(300 * time.Millisecond):
		}
	}
	return fmt.Errorf("spire server did not become ready within 15s")
}

var spireServerTemplate = template.Must(template.New("server.conf").Parse(`server {
    bind_address = "127.0.0.1"
    bind_port = "{{.Port}}"
    trust_domain = "{{.TrustDomain}}"
    data_dir = "{{.DataDir}}"
    log_level = "WARN"
}

plugins {
    DataStore "sql" {
        plugin_data {
            database_type = "sqlite3"
            connection_string = "{{.DataDir}}/datastore.sqlite3"
        }
    }
    KeyManager "memory" {
        plugin_data {}
    }
    NodeAttestor "join_token" {
        plugin_data {}
    }
}
`))

var spireAgentTemplate = template.Must(template.New("agent.conf").Parse(`agent {
    data_dir = "{{.DataDir}}"
    log_level = "WARN"
    server_address = "127.0.0.1"
    server_port = "{{.ServerPort}}"
    socket_path = "{{.SocketDir}}/agent.sock"
    trust_domain = "{{.TrustDomain}}"
}

plugins {
    KeyManager "memory" {
        plugin_data {}
    }
    NodeAttestor "join_token" {
        plugin_data {}
    }
    WorkloadAttestor "unix" {
        plugin_data {}
    }
}
`))

func writeSpireServerConf(path, dataDir, port, trustDomain string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	return spireServerTemplate.Execute(f, map[string]string{
		"DataDir":     dataDir,
		"Port":        port,
		"TrustDomain": trustDomain,
	})
}

func writeSpireAgentConf(path, dataDir, socketDir, serverPort, trustDomain string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	return spireAgentTemplate.Execute(f, map[string]string{
		"DataDir":     dataDir,
		"SocketDir":   socketDir,
		"ServerPort":  serverPort,
		"TrustDomain": trustDomain,
	})
}
