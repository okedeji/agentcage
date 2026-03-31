package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
)

// CageEnv mirrors cage.CageEnv — the config injected by the rootfs assembler.
type CageEnv struct {
	CageID       string   `json:"cage_id"`
	AssessmentID string   `json:"assessment_id"`
	CageType     string   `json:"cage_type"`
	Entrypoint   string   `json:"entrypoint"`
	Objective    string   `json:"objective,omitempty"`
	LLMEndpoint  string   `json:"llm_endpoint,omitempty"`
	NATSAddr     string   `json:"nats_addr,omitempty"`
	ScopeHosts   []string `json:"scope_hosts"`
	ScopePorts   []string `json:"scope_ports,omitempty"`
	ScopePaths   []string `json:"scope_paths,omitempty"`
	TokenBudget  int64    `json:"token_budget,omitempty"`
	ProxyMode    string   `json:"proxy_mode"`
	VulnClass    string   `json:"vuln_class,omitempty"`
}

const configPath = "/etc/agentcage/cage.json"

func main() {
	env, err := loadConfig()
	if err != nil {
		fatal("loading cage config: %v", err)
	}

	fmt.Printf("cage-init: cage=%s assessment=%s type=%s\n", env.CageID, env.AssessmentID, env.CageType)

	// 1. Start findings-sidecar
	sidecar := startService("findings-sidecar",
		"/usr/local/bin/findings-sidecar",
		"-socket", "/var/run/agentcage/findings.sock",
		"-nats", env.NATSAddr,
		"-assessment-id", env.AssessmentID,
		"-cage-id", env.CageID,
	)

	// 2. Start payload-proxy
	var proxy *exec.Cmd
	if env.ProxyMode != "disabled" {
		proxyArgs := []string{
			"-listen", ":8080",
			"-target", fmt.Sprintf("http://%s", env.ScopeHosts[0]),
		}
		if env.VulnClass != "" {
			proxyArgs = append(proxyArgs, "-vuln-class", env.VulnClass)
		}
		if env.LLMEndpoint != "" {
			proxyArgs = append(proxyArgs, "-llm-endpoint", env.LLMEndpoint)
		}
		proxy = startService("payload-proxy", "/usr/local/bin/payload-proxy", proxyArgs...)
	}

	// 3. Set up iptables to redirect outbound HTTP through the proxy
	if proxy != nil {
		setupIPTables()
	}

	// 4. Ensure socket directory exists
	if err := os.MkdirAll("/var/run/agentcage", 0755); err != nil {
		fatal("creating socket directory: %v", err)
	}

	// 5. Export environment variables for the agent
	setEnv("AGENTCAGE_CAGE_ID", env.CageID)
	setEnv("AGENTCAGE_ASSESSMENT_ID", env.AssessmentID)
	setEnv("AGENTCAGE_CAGE_TYPE", env.CageType)
	setEnv("AGENTCAGE_SCOPE", strings.Join(env.ScopeHosts, ","))
	setEnv("AGENTCAGE_FINDINGS_SOCKET", "/var/run/agentcage/findings.sock")
	if env.LLMEndpoint != "" {
		setEnv("AGENTCAGE_LLM_ENDPOINT", env.LLMEndpoint)
	}
	if env.TokenBudget > 0 {
		setEnv("AGENTCAGE_TOKEN_BUDGET", fmt.Sprintf("%d", env.TokenBudget))
	}
	if env.Objective != "" {
		setEnv("AGENTCAGE_OBJECTIVE", env.Objective)
	}

	// 6. Exec the agent entrypoint
	// This replaces PID 1 with the agent process. When the agent exits,
	// the VM has no init and shuts down — which is exactly what we want.
	fmt.Printf("cage-init: exec agent: %s\n", env.Entrypoint)

	parts := strings.Fields(env.Entrypoint)
	agentBin, err := exec.LookPath(parts[0])
	if err != nil {
		// Try under /opt/agent if not in PATH
		agentBin = "/opt/agent/" + parts[0]
		if _, statErr := os.Stat(agentBin); statErr != nil {
			fatal("agent binary not found: %s", parts[0])
		}
	}

	agentArgs := parts
	agentArgs[0] = agentBin

	// Don't exec — keep cage-init as PID 1 so we can reap zombies
	// and wait for the agent to exit.
	agentCmd := exec.Command(agentBin, parts[1:]...)
	agentCmd.Stdout = os.Stdout
	agentCmd.Stderr = os.Stderr
	agentCmd.Dir = "/opt/agent"

	if err := agentCmd.Run(); err != nil {
		fmt.Printf("cage-init: agent exited with error: %v\n", err)
		cleanup(sidecar, proxy)
		os.Exit(1)
	}

	fmt.Println("cage-init: agent completed successfully")
	cleanup(sidecar, proxy)
}

func loadConfig() (*CageEnv, error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", configPath, err)
	}
	var env CageEnv
	if err := json.Unmarshal(data, &env); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}
	return &env, nil
}

func startService(name string, bin string, args ...string) *exec.Cmd {
	cmd := exec.Command(bin, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		fmt.Printf("cage-init: warning: failed to start %s: %v\n", name, err)
		return nil
	}
	fmt.Printf("cage-init: started %s (pid=%d)\n", name, cmd.Process.Pid)
	return cmd
}

func setupIPTables() {
	// Redirect all outbound TCP 80/443 through the payload proxy on :8080
	rules := [][]string{
		{"iptables", "-t", "nat", "-A", "OUTPUT", "-p", "tcp", "--dport", "80", "-j", "REDIRECT", "--to-port", "8080"},
		{"iptables", "-t", "nat", "-A", "OUTPUT", "-p", "tcp", "--dport", "443", "-j", "REDIRECT", "--to-port", "8080"},
	}
	for _, args := range rules {
		cmd := exec.Command(args[0], args[1:]...)
		if out, err := cmd.CombinedOutput(); err != nil {
			fmt.Printf("cage-init: warning: iptables rule failed: %v\n%s\n", err, out)
		}
	}
	fmt.Println("cage-init: iptables redirect rules applied")
}

func setEnv(key, value string) {
	os.Setenv(key, value) //nolint:errcheck
}

func cleanup(procs ...*exec.Cmd) {
	for _, cmd := range procs {
		if cmd != nil && cmd.Process != nil {
			_ = cmd.Process.Signal(syscall.SIGTERM)
		}
	}
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "cage-init: fatal: "+format+"\n", args...)
	os.Exit(1)
}
