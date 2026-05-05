package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/okedeji/agentcage/internal/cagefile"
	"github.com/okedeji/agentcage/internal/config"
	"github.com/okedeji/agentcage/internal/embedded"
)

func cmdAgents(args []string) {
	if len(args) == 0 {
		printAgentsUsage()
		os.Exit(1)
	}

	switch args[0] {
	case "list", "ls":
		cmdAgentsList()
	case "inspect":
		cmdAgentsInspect(args[1:])
	case "rm", "remove":
		cmdAgentsRemove(args[1:])
	case "prune":
		cmdAgentsPrune()
	case "purge":
		cmdAgentsPurge()
	default:
		fmt.Fprintf(os.Stderr, "unknown agents subcommand: %s\n\n", args[0])
		printAgentsUsage()
		os.Exit(1)
	}
}

func cmdAgentsList() {
	dir := bundleStoreDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Println("No agents stored.")
			return
		}
		fmt.Fprintf(os.Stderr, "error reading bundle store: %v\n", err)
		os.Exit(1)
	}

	ts := cagefile.NewTagStore(tagStorePath())

	count := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".cage") {
			continue
		}
		ref := strings.TrimSuffix(e.Name(), ".cage")
		info, _ := e.Info()

		sizeMB := float64(info.Size()) / (1024 * 1024)
		name := agentName(filepath.Join(dir, e.Name()))
		tags := ts.TagsForRef(ref)
		tagStr := ""
		if len(tags) > 0 {
			tagStr = "[" + strings.Join(tags, ", ") + "]"
		}

		fmt.Printf("  %s  %-20s  %.1f MB  %s  %s\n",
			ref[:12], name, sizeMB, info.ModTime().Format("2006-01-02 15:04"), tagStr)
		count++
	}

	if count == 0 {
		fmt.Println("No agents stored. Run 'agentcage pack <dir>' to create one.")
	} else {
		fmt.Printf("\n  %d agent(s)\n", count)
	}
}

func cmdAgentsInspect(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: agentcage agents inspect <ref|name:tag>")
		os.Exit(1)
	}

	store, err := cagefile.NewBundleStore(bundleStoreDir())
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	fullRef, err := resolveAgentQuery(store, args[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	f, err := os.Open(store.Path(fullRef))
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	defer func() { _ = f.Close() }()

	manifest, err := cagefile.ReadManifestFromBundle(f)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading manifest: %v\n", err)
		os.Exit(1)
	}

	ts := cagefile.NewTagStore(tagStorePath())
	tags := ts.TagsForRef(fullRef)

	info, _ := os.Stat(store.Path(fullRef))
	sizeMB := float64(info.Size()) / (1024 * 1024)

	fmt.Printf("  Ref         %s\n", fullRef[:12])
	fmt.Printf("  Full ref    %s\n", fullRef)
	fmt.Printf("  Name        %s\n", manifest.Name)
	if len(tags) > 0 {
		fmt.Printf("  Tags        %s\n", strings.Join(tags, ", "))
	}
	fmt.Printf("  Runtime     %s\n", manifest.Runtime)
	fmt.Printf("  Entrypoint  %s\n", manifest.Entrypoint)
	fmt.Printf("  Size        %.1f MB\n", sizeMB)
	fmt.Printf("  Hash        %s\n", manifest.FilesHash)
	if len(manifest.SystemDeps) > 0 {
		fmt.Printf("  Tools       %s\n", strings.Join(manifest.SystemDeps, ", "))
	}
}

func cmdAgentsRemove(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: agentcage agents rm <ref|name:tag> [...]")
		os.Exit(1)
	}

	store, err := cagefile.NewBundleStore(bundleStoreDir())
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	ts := cagefile.NewTagStore(tagStorePath())

	hasError := false
	for _, query := range args {
		fullRef, resolveErr := resolveAgentQuery(store, query)
		if resolveErr != nil {
			fmt.Fprintf(os.Stderr, "  ✗  %s: %v\n", query, resolveErr)
			hasError = true
			continue
		}

		// Remove all tags pointing to this ref.
		for _, tag := range ts.TagsForRef(fullRef) {
			_ = ts.Untag(tag)
		}

		if err := os.Remove(store.Path(fullRef)); err != nil {
			fmt.Fprintf(os.Stderr, "  ✗  %s: %v\n", query, err)
			hasError = true
			continue
		}
		fmt.Printf("  ✓  removed %s\n", fullRef[:12])
	}
	if hasError {
		os.Exit(1)
	}
}

func cmdAgentsPrune() {
	dir := bundleStoreDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Println("No agents stored.")
			return
		}
		fmt.Fprintf(os.Stderr, "error reading bundle store: %v\n", err)
		os.Exit(1)
	}

	ts := cagefile.NewTagStore(tagStorePath())
	store, _ := cagefile.NewBundleStore(dir)

	// Remove untagged refs.
	removed := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".cage") {
			continue
		}
		ref := strings.TrimSuffix(e.Name(), ".cage")

		if tags := ts.TagsForRef(ref); len(tags) > 0 {
			continue
		}

		path := filepath.Join(dir, e.Name())
		if err := os.Remove(path); err != nil {
			fmt.Fprintf(os.Stderr, "  ✗  %s: %v\n", ref[:12], err)
			continue
		}
		fmt.Printf("  ✓  pruned %s\n", ref[:12])
		removed++
	}

	// Remove orphan tags (point to refs that no longer exist).
	orphans := 0
	tags, _ := ts.List()
	for name, ref := range tags {
		if store != nil && !store.Exists(ref) {
			_ = ts.Untag(name)
			fmt.Printf("  ✓  removed orphan tag %s\n", name)
			orphans++
		}
	}

	if removed == 0 && orphans == 0 {
		fmt.Println("  Nothing to prune")
	} else {
		if removed > 0 {
			fmt.Printf("\n  Pruned %d untagged agent(s)\n", removed)
		}
		if orphans > 0 {
			fmt.Printf("  Removed %d orphan tag(s)\n", orphans)
		}
	}
}

func bundleStoreDir() string {
	return filepath.Join(embedded.DataDir(), "bundles")
}

func tagStorePath() string {
	return filepath.Join(config.HomeDir(), "data", "tags.json")
}

func agentName(cagePath string) string {
	f, err := os.Open(cagePath)
	if err != nil {
		return "(unknown)"
	}
	defer func() { _ = f.Close() }()

	manifest, err := cagefile.ReadManifestFromBundle(f)
	if err != nil {
		return "(unknown)"
	}
	return manifest.Name
}

// resolveAgentQuery resolves a tag (name:tag), bare name (implies
// :latest), or hex ref prefix to a full bundle ref.
func resolveAgentQuery(store *cagefile.BundleStore, query string) (string, error) {
	ts := cagefile.NewTagStore(tagStorePath())

	if strings.Contains(query, ":") {
		ref, err := ts.Resolve(query)
		if err == nil {
			return ref, nil
		}
	}

	fullRef, err := store.Resolve(query)
	if err == nil {
		return fullRef, nil
	}

	if !strings.Contains(query, ":") {
		ref, tagErr := ts.Resolve(query + ":latest")
		if tagErr == nil {
			return ref, nil
		}
	}

	return "", fmt.Errorf("agent '%s' not found", query)
}

func cmdAgentsPurge() {
	dir := bundleStoreDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Println("No agents stored.")
			return
		}
		fmt.Fprintf(os.Stderr, "error reading bundle store: %v\n", err)
		os.Exit(1)
	}

	removed := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".cage") {
			continue
		}
		path := filepath.Join(dir, e.Name())
		if err := os.Remove(path); err != nil {
			fmt.Fprintf(os.Stderr, "  ✗  %s: %v\n", e.Name(), err)
			continue
		}
		removed++
	}

	// Wipe all tags.
	ts := cagefile.NewTagStore(tagStorePath())
	tags, _ := ts.List()
	for name := range tags {
		_ = ts.Untag(name)
	}

	if removed == 0 {
		fmt.Println("  Nothing to purge")
	} else {
		fmt.Printf("  Purged %d agent(s) and all tags\n", removed)
	}
}

func printAgentsUsage() {
	fmt.Fprintf(os.Stderr, `Usage: agentcage agents <subcommand>

Manage stored agents.

Subcommands:
  list, ls            List all stored agents
  inspect <ref|tag>   Show agent details
  rm <ref|tag>        Remove an agent and its tags
  prune               Remove all untagged agents
  purge               Remove ALL agents and tags

Examples:
  agentcage agents list
  agentcage agents inspect agent-starter:latest
  agentcage agents rm agent-starter:v1.0
  agentcage agents prune
  agentcage agents purge
`)
}
