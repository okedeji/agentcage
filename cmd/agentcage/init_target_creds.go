package main

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/okedeji/agentcage/internal/cage"
	"github.com/okedeji/agentcage/internal/identity"
)

// vaultTargetCredentialReader bridges identity.SecretReader (Vault, KV
// of string->any) to cage.TargetCredentialReader (raw JSON bytes the
// FetchTargetCredentials activity hands to cage-init as the cage env
// var AGENTCAGE_TARGET_CREDENTIALS). It reads from the target/<key>
// prefix carved out in identity.TargetPrefix; the prefix is the trust
// boundary between target credentials and orchestrator infra secrets
// and must not be crossed.
type vaultTargetCredentialReader struct {
	reader identity.SecretReader
}

func newVaultTargetCredentialReader(reader identity.SecretReader) cage.TargetCredentialReader {
	if reader == nil {
		return nil
	}
	return &vaultTargetCredentialReader{reader: reader}
}

func (v *vaultTargetCredentialReader) ReadTargetCredentials(ctx context.Context, key string) ([]byte, error) {
	if key == "" {
		return nil, fmt.Errorf("target credential key is empty")
	}
	data, err := v.reader.ReadSecret(ctx, identity.TargetPrefix+key)
	if err != nil {
		return nil, fmt.Errorf("reading target/%s: %w", key, err)
	}
	if data == nil {
		return nil, fmt.Errorf("target/%s not found in vault", key)
	}
	// agentcage vault put stores either the parsed JSON object directly
	// (when value starts with '{') or wraps as {"value": <raw>}. The cage
	// env expects the JSON object form, so unwrap the {"value": ...}
	// shape to the raw string if that's what's there.
	if len(data) == 1 {
		if raw, ok := data["value"].(string); ok {
			return []byte(raw), nil
		}
	}
	out, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("marshaling target/%s: %w", key, err)
	}
	return out, nil
}
