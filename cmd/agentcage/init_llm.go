package main

import (
	"context"
	"fmt"

	"github.com/go-logr/logr"

	"github.com/okedeji/agentcage/internal/alert"
	"github.com/okedeji/agentcage/internal/config"
	"github.com/okedeji/agentcage/internal/gateway"
	"github.com/okedeji/agentcage/internal/identity"
)

func buildLLMClient(ctx context.Context, cfg *config.Config, secrets identity.SecretReader, alertDispatcher *alert.Dispatcher, log logr.Logger) (*gateway.Client, *gateway.TokenMeter, string, error) {
	meter := gateway.NewTokenMeter()
	budgetEnforcer := gateway.NewBudgetEnforcer(meter)

	if cfg.LLM.Endpoint == "" {
		return nil, nil, "", fmt.Errorf("llm.endpoint is required: the assessment coordinator and discovery cages cannot run without an LLM\n  Set it in config: llm:\n                      endpoint: \"https://api.anthropic.com/v1\"\n  Then store the key: agentcage vault put orchestrator llm-api-key <key>")
	}

	var apiKey string
	if secrets != nil {
		var err error
		apiKey, err = identity.ReadSecretValue(ctx, secrets, identity.PathLLMKey)
		if err != nil {
			return nil, nil, "", fmt.Errorf("reading LLM API key from Vault: %w", err)
		}
	}
	client := gateway.NewClient(cfg.LLM.Endpoint, apiKey, cfg.LLM.Timeout, meter, budgetEnforcer, alertDispatcher)
	log.Info("LLM gateway client configured", "endpoint", cfg.LLM.Endpoint, "auth", apiKey != "")
	return client, meter, apiKey, nil
}
