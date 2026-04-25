package main

import (
	"context"
	"database/sql"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"time"

	_ "github.com/lib/pq"

	"github.com/okedeji/agentcage/internal/config"
	"github.com/okedeji/agentcage/internal/embedded"
	"github.com/okedeji/agentcage/internal/identity"
	"github.com/okedeji/agentcage/migrations"
)

func cmdDB(args []string) {
	if len(args) > 0 && args[0] == "migrate" {
		cmdDBMigrate(args[1:])
		return
	}

	fs := flag.NewFlagSet("db", flag.ExitOnError)
	fs.Usage = printDBUsage
	showURL := fs.Bool("url", false, "print connection string only")
	query := fs.String("query", "", "run a SQL query")
	_ = fs.Parse(args)

	dbURL := resolveDBURL()

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

	fmt.Println("Connecting to Postgres...")
	psql := exec.Command("psql", dbURL)
	psql.Stdin = os.Stdin
	psql.Stdout = os.Stdout
	psql.Stderr = os.Stderr
	if err := psql.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func cmdDBMigrate(_ []string) {
	dbURL := resolveDBURL()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	defer func() { _ = db.Close() }()

	if err := db.PingContext(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "error connecting to database: %v\n", err)
		os.Exit(1)
	}

	applied, err := migrations.Up(ctx, db)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error running migrations: %v\n", err)
		os.Exit(1)
	}

	if len(applied) == 0 {
		fmt.Println("Database is up to date.")
		return
	}
	for _, name := range applied {
		fmt.Printf("  applied: %s\n", name)
	}
	fmt.Printf("\n%d migration(s) applied.\n", len(applied))
}

// resolveDBURL returns the Postgres connection URL from config.
// Uses embedded Postgres by default; external Postgres if configured
// (reads URL from Vault).
func resolveDBURL() string {
	cfg := config.Defaults()
	if resolved := config.Resolve(""); resolved != "" {
		override, err := config.Load(resolved)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error loading config: %v\n", err)
			os.Exit(1)
		}
		cfg = config.Merge(cfg, override)
	}

	if cfg.Infrastructure.IsExternalPostgres() {
		reader := mustBuildVaultCLIClient()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		val, err := identity.ReadSecretValue(ctx, reader, identity.PathPostgresURL)
		if err != nil || val == "" {
			fmt.Fprintf(os.Stderr, "error: external Postgres URL not found in Vault at %s\n", identity.PathPostgresURL)
			os.Exit(1)
		}
		return val
	}

	dbURL, err := embedded.PostgresURL()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	return dbURL
}

func printDBUsage() {
	fmt.Fprintf(os.Stderr, `usage: agentcage db [subcommand] [flags]

Interact with the agentcage database (embedded or external).

Subcommands:
  migrate           Apply pending migrations and exit

Flags:
  --url             Print the connection URL (contains credentials)
  --query <sql>     Run a SQL query and exit

Without flags or subcommands, opens an interactive psql session.

Examples:
  agentcage db
  agentcage db migrate
  agentcage db --query "SELECT count(*) FROM findings"
  agentcage db --url
`)
}
