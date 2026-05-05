package main

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/okedeji/agentcage/internal/cagefile"
	"github.com/okedeji/agentcage/internal/config"
	"github.com/okedeji/agentcage/internal/embedded"
)

// prepareBundle resolves an agent query to a full bundle ref in the
// store. Accepts name:tag, bare name (implies :latest), or hex ref prefix.
func prepareBundle(ctx context.Context, query string) (string, error) {
	storeDir := filepath.Join(embedded.DataDir(), "bundles")
	store, err := cagefile.NewBundleStore(storeDir)
	if err != nil {
		return "", fmt.Errorf("opening bundle store: %w", err)
	}

	tagStorePath := filepath.Join(config.HomeDir(), "data", "tags.json")
	ts := cagefile.NewTagStore(tagStorePath)

	// name:tag form — resolve via tag store.
	if strings.Contains(query, ":") {
		ref, err := ts.Resolve(query)
		if err == nil {
			return ref, nil
		}
	}

	// All hex characters — treat as ref prefix in the bundle store.
	if isHexString(query) {
		fullRef, err := store.Resolve(query)
		if err == nil {
			return fullRef, nil
		}
	}

	// Bare name — try name:latest in tag store.
	if !isHexString(query) {
		ref, err := ts.Resolve(query + ":latest")
		if err == nil {
			return ref, nil
		}
	}

	if ctx.Err() != nil {
		return "", ctx.Err()
	}

	return "", fmt.Errorf("agent '%s' not found — run 'agentcage pack' first", query)
}

func isHexString(s string) bool {
	if len(s) == 0 {
		return false
	}
	for _, c := range s {
		isHex := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
		if !isHex {
			return false
		}
	}
	return true
}
