package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/okedeji/agentcage/internal/config"
)

// version is set at build time via -ldflags:
//
//	go build -ldflags "-X main.version=1.2.3" ./cmd/agentcage/
//
// Falls back to "dev" for local builds without ldflags.
var version = "dev"

func main() {
	// Parse global flags before the subcommand. Flags like --home and
	// --config must be set before any package reads HomeDir() or Resolve().
	var cmd string
	var args []string
	for i := 1; i < len(os.Args); i++ {
		switch {
		case os.Args[i] == "--home" && i+1 < len(os.Args):
			config.SetHome(os.Args[i+1])
			i++
		case strings.HasPrefix(os.Args[i], "--home="):
			config.SetHome(strings.TrimPrefix(os.Args[i], "--home="))
		default:
			if cmd == "" {
				cmd = os.Args[i]
			} else {
				args = append(args, os.Args[i])
			}
		}
	}

	if cmd == "" {
		printUsage()
		os.Exit(1)
	}

	switch cmd {
	case "init":
		platformInit(args)
	case "join":
		cmdJoin(args)
	case "stop":
		platformStop(args)
	case "pack":
		cmdPack(args)
	case "run":
		cmdRun(args)
	case "assessments":
		cmdAssessments(args)
	case "findings":
		cmdFindings(args)
	case "report":
		cmdReport(args)
	case "interventions":
		cmdInterventions(args)
	case "fleet":
		cmdFleet(args)
	case "db":
		cmdDB(args)
	case "logs":
		cmdLogs(args)
	case "proof":
		cmdProof(args)
	case "audit":
		cmdAudit(args)
	case "falco":
		cmdFalco(args)
	case "connect":
		cmdConnect(args)
	case "config":
		cmdConfig(args)
	case "access":
		cmdAccess(args)
	case "vault":
		cmdVault(args)
	case "sdk":
		cmdSDK(args)
	case "agents":
		cmdAgents(args)
	case "version":
		fmt.Printf("agentcage %s\n", version)
	case "help", "--help", "-h":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", cmd)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Printf(`agentcage %s — autonomous security assessment in sandboxed cages

Usage: agentcage [--home <dir>] <command> [options]

Global flags:
  --home <dir>        Override home directory (default: ~/.agentcage)

Setup:
  init                Start the orchestrator and embedded services
  join                Join a bare-metal host to the orchestrator's fleet
  stop                Gracefully shut down all services
  connect             Point this CLI at a remote orchestrator
  config              Manage operator config (show, export, import, get)
  access              Manage API keys (create-key, list-keys, revoke-key)
  vault               Manage secrets (put, get, list, delete, rotate, import, migrate)
  sdk                 Install agent SDK for local development

Assess:
  pack <dir>          Bundle an agent directory into a .cage file
  run                 Launch an assessment against a target
  agents              List, inspect, or remove stored agents

Monitor:
  assessments         List or inspect assessments
  findings            List or inspect findings
  report              Generate or export an assessment report
  logs                View or stream cage logs

Operate:
  interventions       List, inspect, or resolve pending interventions
  proof               Manage proof-of-concept validation rules
  fleet               Inspect fleet hosts, pools, and capacity
  audit               Verify, inspect, and export audit logs
  falco               Manage Falco runtime security rules

Maintain:
  db                  Database shell, migrations, and queries

Info:
  version             Print version
  help                Print this help

Run 'agentcage <command> --help' for details on a specific command.
`, version)
}
