package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/okedeji/agentcage/internal/config"
	"github.com/okedeji/agentcage/internal/identity"
)

func cmdVault(args []string) {
	if len(args) < 1 {
		printVaultUsage()
		os.Exit(1)
	}
	switch args[0] {
	case "put":
		cmdVaultPut(args[1:])
	case "get":
		cmdVaultGet(args[1:])
	case "list":
		cmdVaultList(args[1:])
	case "delete":
		cmdVaultDelete(args[1:])
	case "rotate":
		cmdVaultRotate(args[1:])
	case "import":
		cmdVaultImport(args[1:])
	case "migrate":
		cmdVaultMigrate(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown vault command: %s\n\n", args[0])
		printVaultUsage()
		os.Exit(1)
	}
}

func printVaultUsage() {
	fmt.Print(`Usage: agentcage vault <command> [options]

Commands:
  put <scope> <key> <value>    Store a secret (value '-' reads stdin)
  get <scope> <key> [--reveal] Read a secret (redacted by default)
  list <scope>                 List secrets in a scope
  delete <scope> <key> [--force]  Delete a secret
  rotate <scope> <key> <value> Replace a secret (logged as rotation)
  import --from-file <path>    Bulk import from key=value file
  migrate --to-external        Copy embedded Vault secrets to external Vault

Scopes:
  orchestrator    Infrastructure secrets (LLM, Temporal, Fleet, NATS, Judge keys)
  target          Customer-provided target credentials (per-assessment)

`)
}

func cmdVaultPut(args []string) {
	if len(args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: agentcage vault put <scope> <key> <value>")
		os.Exit(1)
	}
	scope, key, value := args[0], args[1], args[2]

	if value == "-" {
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			fmt.Fprintf(os.Stderr, "reading stdin: %v\n", err)
			os.Exit(1)
		}
		value = strings.TrimSpace(string(data))
	}

	reader := mustBuildVaultCLIClient()
	path := mustResolvePath(scope, key)

	var secretData map[string]any
	if strings.HasPrefix(strings.TrimSpace(value), "{") {
		if err := json.Unmarshal([]byte(value), &secretData); err == nil {
			// Valid JSON — store as-is (target credentials).
		} else {
			secretData = map[string]any{"value": value}
		}
	} else {
		secretData = map[string]any{"value": value}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := reader.WriteSecret(ctx, path, secretData); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("stored %s/%s\n", scope, key)
}

func cmdVaultGet(args []string) {
	fs := flag.NewFlagSet("vault get", flag.ExitOnError)
	reveal := fs.Bool("reveal", false, "show actual secret value")
	_ = fs.Parse(args)

	remaining := fs.Args()
	if len(remaining) < 2 {
		fmt.Fprintln(os.Stderr, "usage: agentcage vault get <scope> <key> [--reveal]")
		os.Exit(1)
	}
	scope, key := remaining[0], remaining[1]

	reader := mustBuildVaultCLIClient()
	path := mustResolvePath(scope, key)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	data, err := reader.ReadSecret(ctx, path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	if data == nil {
		fmt.Fprintf(os.Stderr, "not found: %s/%s\n", scope, key)
		os.Exit(1)
	}

	if *reveal {
		out, _ := json.MarshalIndent(data, "", "  ")
		fmt.Println(string(out))
	} else {
		fmt.Printf("%s: ***REDACTED***\n", key)
	}
}

func cmdVaultList(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: agentcage vault list <scope>")
		os.Exit(1)
	}
	scope := args[0]

	reader := mustBuildVaultCLIClient()
	prefix, err := identity.ScopeMetadataPrefix(scope)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	keys, err := reader.ListSecrets(ctx, prefix)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	if len(keys) == 0 {
		fmt.Printf("no secrets in %s scope\n", scope)
		return
	}
	for _, k := range keys {
		fmt.Println(k)
	}
}

func cmdVaultDelete(args []string) {
	fs := flag.NewFlagSet("vault delete", flag.ExitOnError)
	force := fs.Bool("force", false, "skip confirmation")
	_ = fs.Parse(args)

	remaining := fs.Args()
	if len(remaining) < 2 {
		fmt.Fprintln(os.Stderr, "usage: agentcage vault delete <scope> <key> [--force]")
		os.Exit(1)
	}
	scope, key := remaining[0], remaining[1]

	if !*force {
		fmt.Printf("delete %s/%s? [y/N] ", scope, key)
		var answer string
		_, _ = fmt.Scanln(&answer)
		if strings.ToLower(strings.TrimSpace(answer)) != "y" {
			fmt.Println("cancelled")
			return
		}
	}

	reader := mustBuildVaultCLIClient()
	path := mustResolvePath(scope, key)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := reader.DeleteSecret(ctx, path); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("deleted %s/%s\n", scope, key)
}

func cmdVaultRotate(args []string) {
	if len(args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: agentcage vault rotate <scope> <key> <new-value>")
		os.Exit(1)
	}
	scope, key, value := args[0], args[1], args[2]

	reader := mustBuildVaultCLIClient()
	path := mustResolvePath(scope, key)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := reader.WriteSecret(ctx, path, map[string]any{"value": value}); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("rotated %s/%s\n", scope, key)
}

func cmdVaultImport(args []string) {
	fs := flag.NewFlagSet("vault import", flag.ExitOnError)
	fromFile := fs.String("from-file", "", "path to key=value file")
	overwrite := fs.Bool("overwrite", false, "overwrite existing secrets")
	_ = fs.Parse(args)

	if *fromFile == "" {
		fmt.Fprintln(os.Stderr, "usage: agentcage vault import --from-file <path>")
		os.Exit(1)
	}

	f, err := os.Open(*fromFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error opening %s: %v\n", *fromFile, err)
		os.Exit(1)
	}
	defer func() { _ = f.Close() }()

	reader := mustBuildVaultCLIClient()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var imported, skipped int
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}

		vaultPath, known := identity.EnvToVaultPath[key]
		if !known {
			fmt.Printf("  skip: %s (not a recognized AGENTCAGE key)\n", key)
			skipped++
			continue
		}

		if !*overwrite {
			existing, _ := reader.ReadSecret(ctx, vaultPath)
			if existing != nil {
				fmt.Printf("  skip: %s (already exists, use --overwrite)\n", key)
				skipped++
				continue
			}
		}

		if err := reader.WriteSecret(ctx, vaultPath, map[string]any{"value": value}); err != nil {
			fmt.Fprintf(os.Stderr, "  error writing %s: %v\n", key, err)
			continue
		}
		fmt.Printf("  imported: %s → %s\n", key, vaultPath)
		imported++
	}

	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "error reading file: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("\nimported %d, skipped %d\n", imported, skipped)
}

func cmdVaultMigrate(args []string) {
	fs := flag.NewFlagSet("vault migrate", flag.ExitOnError)
	toExternal := fs.Bool("to-external", false, "copy secrets from embedded to external Vault")
	_ = fs.Parse(args)

	if !*toExternal {
		fmt.Fprintln(os.Stderr, "usage: agentcage vault migrate --to-external")
		os.Exit(1)
	}

	cfg, err := config.Load(config.Resolve(""))
	if err != nil {
		fmt.Fprintf(os.Stderr, "error loading config: %v\n", err)
		os.Exit(1)
	}

	if !cfg.Infrastructure.IsExternalVault() {
		fmt.Fprintln(os.Stderr, "error: no external Vault configured in agentcage.yaml (infrastructure.vault.address)")
		os.Exit(1)
	}

	embeddedReader, err := identity.NewVaultTokenSecretReader("http://127.0.0.1:18200", "agentcage-dev-token", nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error connecting to embedded Vault: %v\n", err)
		os.Exit(1)
	}

	externalReader, err := identity.NewVaultTokenSecretReader(cfg.Infrastructure.Vault.Address, os.Getenv("VAULT_TOKEN"), nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error connecting to external Vault: %v\n", err)
		os.Exit(1)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	scopes := []string{"orchestrator", "target"}
	var migrated int
	for _, scope := range scopes {
		metaPrefix, _ := identity.ScopeMetadataPrefix(scope)
		dataPrefix, _ := identity.ScopeDataPrefix(scope)

		keys, err := embeddedReader.ListSecrets(ctx, metaPrefix)
		if err != nil {
			fmt.Printf("  warning: could not list %s scope: %v\n", scope, err)
			continue
		}
		for _, key := range keys {
			srcPath := dataPrefix + key
			data, err := embeddedReader.ReadSecret(ctx, srcPath)
			if err != nil || data == nil {
				continue
			}
			dstPath := srcPath
			if err := externalReader.WriteSecret(ctx, dstPath, data); err != nil {
				fmt.Fprintf(os.Stderr, "  error migrating %s/%s: %v\n", scope, key, err)
				continue
			}
			fmt.Printf("  migrated: %s/%s\n", scope, key)
			migrated++
		}
	}
	fmt.Printf("\nmigrated %d secrets to external Vault\n", migrated)
}

func mustBuildVaultCLIClient() identity.SecretReader {
	// Try embedded Vault first.
	embedded, err := identity.NewVaultTokenSecretReader("http://127.0.0.1:18200", "agentcage-dev-token", nil)
	if err == nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if _, readErr := embedded.ReadSecret(ctx, "secret/data/agentcage/orchestrator/_health"); readErr == nil || !strings.Contains(readErr.Error(), "connection refused") {
			return embedded
		}
	}

	// Fall back to external Vault from config.
	cfg, err := config.Load(config.Resolve(""))
	if err != nil {
		fmt.Fprintf(os.Stderr, "error loading config: %v\n", err)
		os.Exit(1)
	}
	if !cfg.Infrastructure.IsExternalVault() {
		fmt.Fprintln(os.Stderr, "error: no Vault available. Start embedded Vault with 'agentcage init' or configure external Vault in agentcage.yaml")
		os.Exit(1)
	}

	token := os.Getenv("VAULT_TOKEN")
	if token == "" {
		tokenBytes, _ := os.ReadFile(filepath.Join(os.Getenv("HOME"), ".vault-token"))
		token = strings.TrimSpace(string(tokenBytes))
	}
	if token == "" {
		fmt.Fprintln(os.Stderr, "error: set VAULT_TOKEN or login with 'vault login' to use external Vault")
		os.Exit(1)
	}

	reader, err := identity.NewVaultTokenSecretReader(cfg.Infrastructure.Vault.Address, token, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error connecting to Vault: %v\n", err)
		os.Exit(1)
	}
	return reader
}

func mustResolvePath(scope, key string) string {
	clean := filepath.Clean(key)
	if strings.HasPrefix(clean, "..") || strings.HasPrefix(clean, "/") {
		fmt.Fprintf(os.Stderr, "error: invalid key %q (path traversal not allowed)\n", key)
		os.Exit(1)
	}
	prefix, err := identity.ScopeDataPrefix(scope)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	return prefix + clean
}
