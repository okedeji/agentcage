package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/go-logr/logr"
	"github.com/okedeji/agentcage/internal/config"
	"github.com/okedeji/agentcage/internal/embedded"
)

func cmdJoin(args []string) {
	fs := flag.NewFlagSet("join", flag.ExitOnError)
	orchestrator := fs.String("orchestrator", "", "orchestrator address (host:port)")
	apiKey := fs.String("api-key", "", "API key for authentication")
	insecureFlag := fs.Bool("insecure", false, "skip TLS")
	rootfsURL := fs.String("rootfs-url", "", "URL to download cage rootfs from")
	_ = fs.Parse(args)

	if *orchestrator == "" || *apiKey == "" {
		fmt.Fprintln(os.Stderr, "usage: agentcage join --orchestrator <addr> --api-key <key>")
		fmt.Fprintln(os.Stderr, "\nSets up a bare-metal host to run cages. Downloads Firecracker,")
		fmt.Fprintln(os.Stderr, "Falco, SPIRE agent, and Nomad client. Configures them to connect")
		fmt.Fprintln(os.Stderr, "to the orchestrator's services and starts them via systemd.")
		fmt.Fprintln(os.Stderr, "\nFlags:")
		fmt.Fprintln(os.Stderr, "  --orchestrator  orchestrator address (required)")
		fmt.Fprintln(os.Stderr, "  --api-key       API key (required)")
		fmt.Fprintln(os.Stderr, "  --insecure      skip TLS (dev only)")
		fmt.Fprintln(os.Stderr, "  --rootfs-url    URL to download cage rootfs")
		os.Exit(1)
	}

	fmt.Println("Connecting to orchestrator...")
	conn, err := connectInitial(*orchestrator, *apiKey, *insecureFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	defer func() { _ = conn.Close() }()

	fmt.Println("Fetching config and service endpoints...")
	resp, err := fetchConfigAndCA(conn)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error fetching config: %v\n", err)
		os.Exit(1)
	}

	// Save CA cert for future connections.
	home := config.HomeDir()
	if len(resp.GetCaCert()) > 0 {
		caPath := filepath.Join(home, "ca.pem")
		if err := os.MkdirAll(home, 0755); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		_ = os.WriteFile(caPath, resp.GetCaCert(), 0644)
	}

	endpoints := resp.GetServiceEndpoints()
	if endpoints == nil {
		fmt.Fprintln(os.Stderr, "error: orchestrator did not return service endpoints.")
		fmt.Fprintln(os.Stderr, "Make sure the orchestrator has infrastructure.advertise_address set in its config.")
		os.Exit(1)
	}

	spireAddr := endpoints.GetSpireServer()
	nomadAddr := endpoints.GetNomadServer()
	rootfs := *rootfsURL
	if rootfs == "" {
		rootfs = endpoints.GetRootfsUrl()
	}

	fmt.Printf("  SPIRE server: %s\n", spireAddr)
	fmt.Printf("  Nomad server: %s\n", nomadAddr)
	if rootfs != "" {
		fmt.Printf("  Rootfs URL:   %s\n", rootfs)
	}

	// Download binaries using the same embedded download functions.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	fmt.Println("\nEnsuring directories...")
	if err := embedded.EnsureDirs(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Downloading Firecracker + kernel...")
	log := logr.Discard()
	fc := embedded.NewFirecrackerDownloader(log, version)
	if err := fc.Download(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "error downloading Firecracker: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Downloading Falco...")
	falco := embedded.NewFalcoService(log, version)
	if err := falco.Download(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "error downloading Falco: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Downloading SPIRE...")
	spire := embedded.NewSPIREService(log)
	if err := spire.Download(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "error downloading SPIRE: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Downloading Nomad...")
	nomad := embedded.NewNomadService(log)
	if err := nomad.Download(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "error downloading Nomad: %v\n", err)
		os.Exit(1)
	}

	if rootfs != "" {
		rootfsPath := filepath.Join(embedded.DataDir(), "vm", "cage-rootfs.img")
		if _, err := os.Stat(rootfsPath); os.IsNotExist(err) {
			fmt.Printf("Downloading cage rootfs from %s...\n", rootfs)
			if dlErr := embedded.DownloadFile(ctx, rootfs, rootfsPath); dlErr != nil {
				fmt.Fprintf(os.Stderr, "error downloading rootfs: %v\n", dlErr)
				os.Exit(1)
			}
		}
	}

	// Write SPIRE agent config pointing at orchestrator's SPIRE server.
	fmt.Println("\nConfiguring SPIRE agent...")
	spireDataDir := embedded.ServiceDataDir("spire")
	if err := os.MkdirAll(spireDataDir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	socketDir := filepath.Join(embedded.RunDir(), "spire")
	if err := os.MkdirAll(socketDir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	// Extract host:port from spireAddr.
	spireHost, spirePort := splitHostPort(spireAddr, "18081")
	agentConf := fmt.Sprintf(`agent {
    data_dir = "%s"
    log_level = "WARN"
    server_address = "%s"
    server_port = "%s"
    socket_path = "%s/agent.sock"
    trust_domain = "agentcage.local"
}
plugins {
    NodeAttestor "join_token" { plugin_data {} }
    WorkloadAttestor "unix" { plugin_data {} }
    KeyManager "disk" { plugin_data { directory = "%s" } }
}
`, spireDataDir, spireHost, spirePort, socketDir, spireDataDir)

	agentConfPath := filepath.Join(spireDataDir, "agent.conf")
	if err := os.WriteFile(agentConfPath, []byte(agentConf), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "error writing SPIRE agent config: %v\n", err)
		os.Exit(1)
	}

	// Write Nomad client config pointing at orchestrator's Nomad server.
	fmt.Println("Configuring Nomad client...")
	nomadDataDir := embedded.ServiceDataDir("nomad")
	if err := os.MkdirAll(nomadDataDir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	nomadConf := fmt.Sprintf(`bind_addr = "0.0.0.0"
data_dir  = "%s"
client {
  enabled = true
  servers = ["%s"]
}
plugin "raw_exec" {
  config { enabled = true }
}
`, nomadDataDir, nomadAddr)

	nomadConfPath := filepath.Join(nomadDataDir, "client.hcl")
	if err := os.WriteFile(nomadConfPath, []byte(nomadConf), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "error writing Nomad client config: %v\n", err)
		os.Exit(1)
	}

	// Write systemd units.
	fmt.Println("Writing systemd units...")
	units := map[string]string{
		"agentcage-falco": fmt.Sprintf(`[Unit]
Description=Falco Runtime Security (agentcage)
After=network.target
[Service]
ExecStart=%s/falco -o engine.kind=modern_ebpf -o json_output=true -o buffered_outputs=false -o file_output.enabled=true -o file_output.filename=%s/falco/alerts.jsonl -o file_output.keep_alive=true -r %s/falco/rules.d
Restart=always
[Install]
WantedBy=multi-user.target
`, embedded.BinDir(), embedded.RunDir(), embedded.RunDir()),

		"agentcage-spire-agent": fmt.Sprintf(`[Unit]
Description=SPIRE Agent (agentcage)
After=network.target
[Service]
ExecStart=%s/spire-agent run -config %s
Restart=always
[Install]
WantedBy=multi-user.target
`, embedded.BinDir(), agentConfPath),

		"agentcage-nomad-client": fmt.Sprintf(`[Unit]
Description=Nomad Client (agentcage)
After=network.target
[Service]
ExecStart=%s/nomad agent -config=%s
Restart=always
[Install]
WantedBy=multi-user.target
`, embedded.BinDir(), nomadConfPath),
	}

	for name, content := range units {
		unitPath := fmt.Sprintf("/etc/systemd/system/%s.service", name)
		if err := os.WriteFile(unitPath, []byte(content), 0644); err != nil {
			fmt.Fprintf(os.Stderr, "error writing %s: %v\n", unitPath, err)
			os.Exit(1)
		}
	}

	// Reload and start services.
	fmt.Println("Starting services...")
	if err := exec.Command("systemctl", "daemon-reload").Run(); err != nil {
		fmt.Fprintf(os.Stderr, "warning: systemctl daemon-reload failed: %v\n", err)
	}
	for name := range units {
		if err := exec.Command("systemctl", "enable", "--now", name).Run(); err != nil {
			fmt.Fprintf(os.Stderr, "warning: failed to start %s: %v\n", name, err)
		} else {
			fmt.Printf("  %s started\n", name)
		}
	}

	fmt.Println("\nCage host ready.")
	fmt.Printf("SPIRE agent socket: %s/agent.sock\n", socketDir)
	fmt.Printf("Nomad client connecting to: %s\n", nomadAddr)
}

func splitHostPort(addr, defaultPort string) (string, string) {
	for i := len(addr) - 1; i >= 0; i-- {
		if addr[i] == ':' {
			return addr[:i], addr[i+1:]
		}
	}
	return addr, defaultPort
}

