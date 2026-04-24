package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"

	"github.com/okedeji/agentcage/internal/embedded"
)

func cmdDB(args []string) {
	fs := flag.NewFlagSet("db", flag.ExitOnError)
	showURL := fs.Bool("url", false, "print connection string only")
	query := fs.String("query", "", "run a SQL query")
	_ = fs.Parse(args)

	dbURL, urlErr := embedded.PostgresURL()
	if urlErr != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", urlErr)
		os.Exit(1)
	}

	if *showURL {
		fmt.Fprintln(os.Stderr, "warning: URL contains embedded credentials")
		fmt.Println(dbURL)
		return
	}

	if _, err := exec.LookPath("psql"); err != nil {
		fmt.Fprintln(os.Stderr, "error: psql not found. Install it with: brew install libpq (macOS) or apt install postgresql-client (Linux)")
		os.Exit(1)
	}

	if *query != "" {
		psql := exec.Command("psql", dbURL, "-c", *query)
		psql.Stdout = os.Stdout
		psql.Stderr = os.Stderr
		if err := psql.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "error running query: %v\n", err)
			os.Exit(1)
		}
		return
	}

	fmt.Println("Connecting to embedded Postgres...")
	psql := exec.Command("psql", dbURL)
	psql.Stdin = os.Stdin
	psql.Stdout = os.Stdout
	psql.Stderr = os.Stderr
	if err := psql.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}
