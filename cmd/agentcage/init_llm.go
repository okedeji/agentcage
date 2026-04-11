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

func buildLLMClient(ctx context.Context, cfg *config.Config, secrets identity.SecretReader, alertDispatcher *alert.Dispatcher, log logr.Logger) (*gateway.Client, *gateway.TokenMeter, error) {
	meter := gateway.NewTokenMeter()
	budgetEnforcer := gateway.NewBudgetEnforcer(meter)

	if cfg.LLM.Endpoint == "" {
		if cfg.LLMRequiredDefault() {
			return nil, nil, fmt.Errorf("posture=strict: llm.endpoint is required (the assessment coordinator and discovery cages cannot run without an LLM)")
		}
		log.Info("WARNING: no LLM endpoint configured. Assessment coordinator will not be able to plan cages.")
		return nil, meter, nil
	}

	var apiKey string
	if secrets != nil {
		var err error
		apiKey, err = identity.ReadSecretValue(ctx, secrets, identity.PathLLMKey)
		if err != nil {
			return nil, nil, fmt.Errorf("reading LLM API key from Vault: %w", err)
		}
	}
	client := gateway.NewClient(cfg.LLM.Endpoint, apiKey, cfg.LLM.Timeout, meter, budgetEnforcer, alertDispatcher)
	log.Info("LLM gateway client configured", "endpoint", cfg.LLM.Endpoint, "auth", apiKey != "")
	return client, meter, nil
}
