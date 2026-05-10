package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	pb "github.com/okedeji/agentcage/api/proto"
	"github.com/okedeji/agentcage/internal/config"
	agentgrpc "github.com/okedeji/agentcage/internal/grpc"
	"gopkg.in/yaml.v3"
)

func cmdAccess(args []string) {
	if len(args) < 1 {
		printAccessUsage()
		os.Exit(1)
	}

	switch args[0] {
	case "create-key":
		cmdAccessCreateKey(args[1:])
	case "list-keys":
		cmdAccessListKeys(args[1:])
	case "revoke-key":
		cmdAccessRevokeKey(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown access subcommand: %s\n\n", args[0])
		printAccessUsage()
		os.Exit(1)
	}
}

func cmdAccessCreateKey(args []string) {
	fs := flag.NewFlagSet("access create-key", flag.ExitOnError)
	name := fs.String("name", "", "name for the key (e.g. ci-runner)")
	_ = fs.Parse(args)

	if *name == "" {
		fmt.Fprintln(os.Stderr, "usage: agentcage access create-key --name <name>")
		os.Exit(1)
	}

	keyBytes := make([]byte, 32)
	if _, err := rand.Read(keyBytes); err != nil {
		fmt.Fprintf(os.Stderr, "error generating key: %v\n", err)
		os.Exit(1)
	}
	key := hex.EncodeToString(keyBytes)
	hash := agentgrpc.HashAPIKey(key)

	if remote := tryRemoteConfig(); remote != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if _, err := remote.CreateAPIKey(ctx, &pb.CreateAPIKeyRequest{Name: *name, KeyHash: hash}); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	} else {
		cfg, path := loadOrCreateConfig()
		for _, existing := range cfg.Access.APIKeys {
			if existing.Name == *name {
				fmt.Fprintf(os.Stderr, "error: key with name %q already exists. Revoke it first.\n", *name)
				os.Exit(1)
			}
		}
		cfg.Access.APIKeys = append(cfg.Access.APIKeys, config.APIKeyEntry{
			Name:    *name,
			KeyHash: hash,
		})
		if err := saveConfig(cfg, path); err != nil {
			fmt.Fprintf(os.Stderr, "error saving config: %v\n", err)
			os.Exit(1)
		}
	}

	fmt.Printf("API key created for %q.\n", *name)
	fmt.Printf("Key: %s\n", key)
	fmt.Println("\nSave this key now. It cannot be retrieved later.")
	fmt.Printf("Use it with: agentcage connect <address> --api-key %s\n", key)
}

func cmdAccessListKeys(_ []string) {
	if remote := tryRemoteConfig(); remote != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		resp, err := remote.ListAPIKeys(ctx, &pb.ListAPIKeysRequest{})
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		if len(resp.GetKeys()) == 0 {
			fmt.Println("No API keys configured.")
			return
		}
		fmt.Println("API keys:")
		for _, k := range resp.GetKeys() {
			fmt.Printf("  %-20s %s\n", k.GetName(), k.GetKeyHashPrefix())
		}
		return
	}

	cfg, _ := loadOrCreateConfig()

	if len(cfg.Access.APIKeys) == 0 {
		fmt.Println("No API keys configured.")
		return
	}

	fmt.Println("API keys:")
	for _, k := range cfg.Access.APIKeys {
		hash := k.KeyHash
		if len(hash) > 20 {
			hash = hash[:20] + "..."
		}
		fmt.Printf("  %-20s %s\n", k.Name, hash)
	}
}

func cmdAccessRevokeKey(args []string) {
	fs := flag.NewFlagSet("access revoke-key", flag.ExitOnError)
	name := fs.String("name", "", "name of the key to revoke")
	_ = fs.Parse(args)

	if *name == "" {
		fmt.Fprintln(os.Stderr, "usage: agentcage access revoke-key --name <name>")
		os.Exit(1)
	}

	if remote := tryRemoteConfig(); remote != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if _, err := remote.RevokeAPIKey(ctx, &pb.RevokeAPIKeyRequest{Name: *name}); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("API key %q revoked.\n", *name)
		return
	}

	cfg, path := loadOrCreateConfig()

	found := false
	var remaining []config.APIKeyEntry
	for _, k := range cfg.Access.APIKeys {
		if k.Name == *name {
			found = true
			continue
		}
		remaining = append(remaining, k)
	}

	if !found {
		fmt.Fprintf(os.Stderr, "error: no key found with name %q\n", *name)
		os.Exit(1)
	}

	cfg.Access.APIKeys = remaining
	if err := saveConfig(cfg, path); err != nil {
		fmt.Fprintf(os.Stderr, "error saving config: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("API key %q revoked.\n", *name)
}

func loadOrCreateConfig() (*config.Config, string) {
	path := config.DefaultPath()
	cfg := config.Defaults()

	if resolved := config.Resolve(""); resolved != "" {
		override, err := config.Load(resolved)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error loading config: %v\n", err)
			os.Exit(1)
		}
		cfg = config.Merge(cfg, override)
		path = resolved
	}
	return cfg, path
}

func saveConfig(cfg *config.Config, path string) error {
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshaling config: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("creating config directory: %w", err)
	}
	// 0600: config may contain API key hashes.
	return os.WriteFile(path, data, 0600)
}

func printAccessUsage() {
	fmt.Fprintf(os.Stderr, `usage: agentcage access <subcommand>

Manage client authentication.

Subcommands:
  create-key    Generate a new API key
  list-keys     List configured API keys
  revoke-key    Revoke an API key by name

Examples:
  agentcage access create-key --name ci-runner
  agentcage access list-keys
  agentcage access revoke-key --name ci-runner
`)
}
