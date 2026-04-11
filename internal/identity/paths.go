package identity

import (
	"context"
	"fmt"
)

const (
	OrchestratorPrefix         = "secret/data/agentcage/orchestrator/"
	OrchestratorMetadataPrefix = "secret/metadata/agentcage/orchestrator/"
	TargetPrefix               = "secret/data/agentcage/target/"
	TargetMetadataPrefix       = "secret/metadata/agentcage/target/"

	PathLLMKey       = OrchestratorPrefix + "llm-api-key"
	PathTemporalKey  = OrchestratorPrefix + "temporal-api-key"
	PathFleetKey     = OrchestratorPrefix + "fleet-api-key"
	PathNATSURL      = OrchestratorPrefix + "nats-url"
	PathPostgresURL  = OrchestratorPrefix + "postgres-url"
	PathJudgeKey     = OrchestratorPrefix + "judge-api-key"
)

// EnvToVaultPath maps legacy AGENTCAGE_* env var names to Vault paths.
// Used by the vault import command to translate .env files.
var EnvToVaultPath = map[string]string{
	"AGENTCAGE_LLM_API_KEY":      PathLLMKey,
	"AGENTCAGE_TEMPORAL_API_KEY":  PathTemporalKey,
	"AGENTCAGE_FLEET_API_KEY":     PathFleetKey,
	"AGENTCAGE_JUDGE_API_KEY":     PathJudgeKey,
	"AGENTCAGE_NATS_URL":          PathNATSURL,
	"AGENTCAGE_POSTGRES_URL":      PathPostgresURL,
}

func ScopeDataPrefix(scope string) (string, error) {
	switch scope {
	case "orchestrator":
		return OrchestratorPrefix, nil
	case "target":
		return TargetPrefix, nil
	default:
		return "", fmt.Errorf("unknown scope %q (expected: orchestrator, target)", scope)
	}
}

func ScopeMetadataPrefix(scope string) (string, error) {
	switch scope {
	case "orchestrator":
		return OrchestratorMetadataPrefix, nil
	case "target":
		return TargetMetadataPrefix, nil
	default:
		return "", fmt.Errorf("unknown scope %q (expected: orchestrator, target)", scope)
	}
}

// ReadSecretValue reads a single string value from a Vault KV v2 path.
// Returns empty string and nil error if the path does not exist.
func ReadSecretValue(ctx context.Context, reader SecretReader, path string) (string, error) {
	data, err := reader.ReadSecret(ctx, path)
	if err != nil {
		return "", fmt.Errorf("reading %s: %w", path, err)
	}
	if data == nil {
		return "", nil
	}
	v, ok := data["value"].(string)
	if !ok {
		return "", fmt.Errorf("secret at %s: 'value' key is not a string", path)
	}
	return v, nil
}

// ReadSecretJSON reads raw JSON data from a Vault KV v2 path.
// Used for target credentials which are stored as JSON blobs.
// Returns nil and nil error if the path does not exist.
func ReadSecretJSON(ctx context.Context, reader SecretReader, path string) (map[string]any, error) {
	data, err := reader.ReadSecret(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	return data, nil
}
