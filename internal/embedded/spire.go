package embedded

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"text/template"
	"time"

	"github.com/go-logr/logr"
)

const (
	spireVersion     = "1.14.6"
	spireServerPort  = "18081"
	spireTrustDomain = "agentcage.local"
)

func SPIREServerPort() string { return spireServerPort }

// SPIREService manages embedded SPIRE server and agent processes.
type SPIREService struct {
	serverProc *subprocess
	agentProc  *subprocess
	bindAddr   string
	log        logr.Logger
}

func NewSPIREService(log logr.Logger) *SPIREService {
	return &SPIREService{bindAddr: "127.0.0.1", log: log.WithValues("service", "spire")}
}

func NewSPIREServiceWithBind(log logr.Logger, bindAddr string) *SPIREService {
	return &SPIREService{bindAddr: bindAddr, log: log.WithValues("service", "spire")}
}

func (s *SPIREService) Name() string      { return "spire" }
func (s *SPIREService) IsExternal() bool   { return false }

func (s *SPIREService) AgentSocket() string {
	return filepath.Join(RunDir(), "spire", "agent.sock")
}

func (s *SPIREService) Download(ctx context.Context) error {
	serverBin := filepath.Join(BinDir(), "spire-server")
	agentBin := filepath.Join(BinDir(), "spire-agent")

	if _, err := os.Stat(serverBin); err == nil {
		if _, err := os.Stat(agentBin); err == nil {
			return nil
		}
	}

	arch := runtime.GOARCH
	url := fmt.Sprintf("https://github.com/spiffe/spire/releases/download/v%s/spire-%s-linux-%s-musl.tar.gz",
		spireVersion, spireVersion, arch)

	s.log.Info("downloading spire", "version", spireVersion, "url", url)

	archivePath := filepath.Join(BinDir(), "spire-"+spireVersion+".tar.gz")
	if err := downloadBinaryWithLog(ctx, url, archivePath, s.log); err != nil {
		return fmt.Errorf("downloading spire: %w", err)
	}

	f, err := os.Open(archivePath)
	if err != nil {
		return fmt.Errorf("opening spire archive: %w", err)
	}
	defer func() { _ = f.Close() }()

	if err := extractTarGz(f, BinDir()); err != nil {
		_ = os.Remove(archivePath)
		return fmt.Errorf("extracting spire: %w", err)
	}
	_ = os.Remove(archivePath)

	// SPIRE extracts into a versioned directory. Move binaries to BinDir
	extractedDir := filepath.Join(BinDir(), "spire-"+spireVersion)
	for _, bin := range []string{"spire-server", "spire-agent"} {
		src := filepath.Join(extractedDir, "bin", bin)
		dst := filepath.Join(BinDir(), bin)
		if err := os.Rename(src, dst); err != nil {
			return fmt.Errorf("moving %s to bin dir: %w", bin, err)
		}
	}
	_ = os.RemoveAll(extractedDir)

	return nil
}

func (s *SPIREService) Start(ctx context.Context) error {
	dataDir := ServiceDataDir("spire")
	socketDir := filepath.Join(RunDir(), "spire")

	// Clear stale agent data from previous runs. The server
	// regenerates its CA on each start, so cached trust bundles
	// from a prior server instance cause TLS verification failures.
	_ = os.Remove(filepath.Join(dataDir, "agent-data.json"))
	_ = os.Remove(filepath.Join(dataDir, "datastore.sqlite3"))
	_ = os.Remove(filepath.Join(dataDir, "datastore.sqlite3-shm"))
	_ = os.Remove(filepath.Join(dataDir, "datastore.sqlite3-wal"))

	if err := os.MkdirAll(socketDir, 0755); err != nil {
		return fmt.Errorf("creating SPIRE socket directory: %w", err)
	}

	// Generate server config
	serverConf := filepath.Join(dataDir, "server.conf")
	if err := writeSpireServerConf(serverConf, dataDir, socketDir, spireServerPort, spireTrustDomain, s.bindAddr); err != nil {
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

	// Generate a join token for the agent. The token is single-use
	// and consumed during the agent's first attestation.
	// SPIRE server API socket is at <data_dir>/api.sock by default.
	serverBinPath := filepath.Join(BinDir(), "spire-server")
	serverSocket := filepath.Join(socketDir, "server.sock")
	tokenCmd := exec.CommandContext(ctx, serverBinPath,
		"token", "generate",
		"-spiffeID", "spiffe://"+spireTrustDomain+"/agent",
		"-socketPath", serverSocket,
	)
	tokenOut, err := tokenCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("generating SPIRE join token: %w\n%s", err, tokenOut)
	}
	joinToken := extractJoinToken(string(tokenOut))
	if joinToken == "" {
		return fmt.Errorf("failed to parse join token from output: %s", tokenOut)
	}
	s.log.Info("join token generated")

	// Generate agent config
	agentConf := filepath.Join(dataDir, "agent.conf")
	if err := writeSpireAgentConf(agentConf, dataDir, socketDir, spireServerPort, spireTrustDomain); err != nil {
		return fmt.Errorf("writing SPIRE agent config: %w", err)
	}

	// Start agent with the join token
	agentBin := filepath.Join(BinDir(), "spire-agent")
	s.agentProc = newSubprocess("spire-agent", s.log, agentBin,
		"run",
		"-config", agentConf,
		"-joinToken", joinToken,
	)
	if err := s.agentProc.start(ctx); err != nil {
		return fmt.Errorf("starting SPIRE agent: %w", err)
	}

	if err := s.waitAgentReady(ctx); err != nil {
		return fmt.Errorf("waiting for SPIRE agent socket: %w", err)
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

func (s *SPIREService) waitAgentReady(ctx context.Context) error {
	socket := s.AgentSocket()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(socket); err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(300 * time.Millisecond):
		}
	}
	return fmt.Errorf("spire agent socket %s did not appear within 15s", socket)
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
    bind_address = "{{.BindAddr}}"
    bind_port = "{{.Port}}"
    socket_path = "{{.SocketDir}}/server.sock"
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
    insecure_bootstrap = true
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

func writeSpireServerConf(path, dataDir, socketDir, port, trustDomain, bindAddr string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	return spireServerTemplate.Execute(f, map[string]string{
		"DataDir":     dataDir,
		"SocketDir":   socketDir,
		"Port":        port,
		"TrustDomain": trustDomain,
		"BindAddr":    bindAddr,
	})
}

// extractJoinToken parses the token from spire-server token generate output.
// Output format: "Token: <uuid-token>\n"
func extractJoinToken(output string) string {
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Token:") {
			return strings.TrimSpace(strings.TrimPrefix(line, "Token:"))
		}
	}
	return strings.TrimSpace(output)
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
