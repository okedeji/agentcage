package main

import (
	"context"
	"fmt"
	"os"

	agentcage "github.com/okedeji/agentcage"
	"github.com/okedeji/agentcage/internal/config"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	cmd := os.Args[1]
	args := os.Args[2:]

	switch cmd {
	case "cages":
		handleCages(args)
	case "assessments":
		handleAssessments(args)
	case "interventions":
		handleInterventions(args)
	case "fleet":
		handleFleet(args)
	case "audit":
		handleAudit(args)
	case "config":
		handleConfig(args)
	case "help", "--help", "-h":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", cmd)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`agentcage - autonomous security agent cage orchestrator

Usage:
  agentcage <command> <subcommand> [flags]

Commands:
  cages          Manage cages (list, get, destroy)
  assessments    Manage assessments (list, get)
  interventions  Manage interventions (list, resolve)
  fleet          Fleet management (status)
  audit          Audit log operations (verify)
  config         Configuration (get, set, reset)

Use "agentcage <command> --help" for more information.`)
}

func handleCages(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: agentcage cages <list|get|destroy>")
		os.Exit(1)
	}

	switch args[0] {
	case "list":
		printRemoteStub("cages list")
	case "get":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "usage: agentcage cages get <cage-id>")
			os.Exit(1)
		}
		printRemoteStub(fmt.Sprintf("cages get %s", args[1]))
	case "destroy":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "usage: agentcage cages destroy <cage-id>")
			os.Exit(1)
		}
		printRemoteStub(fmt.Sprintf("cages destroy %s", args[1]))
	case "--help", "-h":
		fmt.Println(`Manage cages.

Subcommands:
  list      List all running cages
  get       Get details for a specific cage
  destroy   Destroy a running cage`)
	default:
		fmt.Fprintf(os.Stderr, "unknown cages subcommand: %s\n", args[0])
		os.Exit(1)
	}
}

func handleAssessments(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: agentcage assessments <list|get>")
		os.Exit(1)
	}

	switch args[0] {
	case "list":
		printRemoteStub("assessments list")
	case "get":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "usage: agentcage assessments get <assessment-id>")
			os.Exit(1)
		}
		printRemoteStub(fmt.Sprintf("assessments get %s", args[1]))
	case "--help", "-h":
		fmt.Println(`Manage assessments.

Subcommands:
  list    List all assessments
  get     Get details for a specific assessment`)
	default:
		fmt.Fprintf(os.Stderr, "unknown assessments subcommand: %s\n", args[0])
		os.Exit(1)
	}
}

func handleInterventions(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: agentcage interventions <list|resolve>")
		os.Exit(1)
	}

	switch args[0] {
	case "list":
		printRemoteStub("interventions list")
	case "resolve":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "usage: agentcage interventions resolve <intervention-id> --action <resume|kill|allow|block>")
			os.Exit(1)
		}
		printRemoteStub(fmt.Sprintf("interventions resolve %s", args[1]))
	case "--help", "-h":
		fmt.Println(`Manage interventions.

Subcommands:
  list      List pending interventions
  resolve   Resolve a pending intervention`)
	default:
		fmt.Fprintf(os.Stderr, "unknown interventions subcommand: %s\n", args[0])
		os.Exit(1)
	}
}

func handleFleet(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: agentcage fleet <status>")
		os.Exit(1)
	}

	switch args[0] {
	case "status":
		printRemoteStub("fleet status")
	case "--help", "-h":
		fmt.Println(`Fleet management.

Subcommands:
  status    Show fleet status and capacity`)
	default:
		fmt.Fprintf(os.Stderr, "unknown fleet subcommand: %s\n", args[0])
		os.Exit(1)
	}
}

func handleAudit(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: agentcage audit <verify>")
		os.Exit(1)
	}

	switch args[0] {
	case "verify":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "usage: agentcage audit verify <cage-id>")
			os.Exit(1)
		}
		auditVerify(args[1])
	case "--help", "-h":
		fmt.Println(`Audit log operations.

Subcommands:
  verify    Verify audit chain integrity for a cage`)
	default:
		fmt.Fprintf(os.Stderr, "unknown audit subcommand: %s\n", args[0])
		os.Exit(1)
	}
}

func handleConfig(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: agentcage config <get|set|reset>")
		os.Exit(1)
	}

	switch args[0] {
	case "get":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "usage: agentcage config get <path>")
			os.Exit(1)
		}
		configGet(args[1])
	case "set":
		if len(args) < 3 {
			fmt.Fprintln(os.Stderr, "usage: agentcage config set <path> <value>")
			os.Exit(1)
		}
		configSet(args[1], args[2])
	case "reset":
		configReset()
	case "--help", "-h":
		fmt.Println(`Configuration management (works offline against embedded defaults).

Subcommands:
  get <path>          Get a config value by dot-separated path
  set <path> <value>  Set a config value
  reset               Reset config to embedded defaults`)
	default:
		fmt.Fprintf(os.Stderr, "unknown config subcommand: %s\n", args[0])
		os.Exit(1)
	}
}

func configGet(path string) {
	srv, err := loadConfigServer()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	val, err := srv.GetValue(context.Background(), path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(val)
}

func configSet(path, value string) {
	srv, err := loadConfigServer()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	if err := srv.UpdateValue(context.Background(), path, value); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("%s = %s\n", path, value)
}

func configReset() {
	srv, err := loadConfigServer()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	if err := srv.ResetConfig(context.Background()); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("config reset to defaults")
}

func loadConfigServer() (*config.ConfigServer, error) {
	cfg, err := config.Default(agentcage.DefaultConfigYAML)
	if err != nil {
		return nil, fmt.Errorf("loading default config: %w", err)
	}
	return config.NewConfigServer(cfg), nil
}

func auditVerify(cageID string) {
	fmt.Printf("audit verify: would verify chain integrity for cage %s\n", cageID)
	fmt.Println("(requires audit log export file — use --file flag when available)")
}

func printRemoteStub(operation string) {
	fmt.Fprintf(os.Stderr, "error: %s requires connection to the orchestrator (gRPC client pending)\n", operation)
	fmt.Fprintln(os.Stderr, "hint: the orchestrator exposes cage, assessment, intervention, and fleet services on the gRPC API")
	os.Exit(1)
}
