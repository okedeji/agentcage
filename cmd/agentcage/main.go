package main

import (
	"fmt"
	"os"
)

const version = "0.1.0"

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	cmd := os.Args[1]
	args := os.Args[2:]

	switch cmd {
	case "init":
		cmdInit(args)
	case "stop":
		cmdStop(args)
	case "pack":
		cmdPack(args)
	case "run":
		cmdRun(args)
	case "test":
		cmdTest(args)
	case "status":
		cmdStatus(args)
	case "findings":
		cmdFindings(args)
	case "report":
		cmdReport(args)
	case "interventions":
		cmdInterventions(args)
	case "resolve":
		cmdResolve(args)
	case "fleet":
		cmdFleet(args)
	case "db":
		cmdDB(args)
	case "logs":
		cmdLogs(args)
	case "audit":
		cmdAudit(args)
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
	fmt.Printf(`agentcage %s - orchestrate AI security agents in sandboxed cages

Usage: agentcage <command> [options]

Platform:
  init              Initialize agentcage, download deps, start local services
  stop              Gracefully shut down all local services

Agent:
  pack <dir>        Bundle agent directory into .cage file
  run               Start a full assessment (coordinator spawns many cages)
  test              Boot a single cage for agent development/debugging

Observe:
  status            Show running assessment status, active cages
  findings          List findings from current/specified assessment
  report            Show/export assessment report
  logs              Stream cage logs

Operate:
  interventions     List pending interventions
  resolve           Resolve an intervention (resume/kill/allow/block)
  fleet             Show fleet status (hosts, pools, capacity)
  db                Open psql shell or show connection string
  audit verify      Verify audit chain integrity for a cage

Info:
  version           Show version info
  help              Show this help

`, version)
}
