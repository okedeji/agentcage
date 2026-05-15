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

func buildLLMClient(ctx context.Context, cfg *config.Config, configServer *config.Server, secrets identity.SecretReader, alertDispatcher *alert.Dispatcher, log logr.Logger) (*gateway.Client, *gateway.TokenMeter, string, error) {
	meter := gateway.NewTokenMeter()
	budgetEnforcer := gateway.NewBudgetEnforcer(meter)

	if cfg.LLM.Endpoint == "" {
		log.Info("llm.endpoint not set at startup, can be set later via: agentcage config set llm.endpoint <url>")
	}

	var apiKey string
	if secrets != nil {
		var err error
		apiKey, err = identity.ReadSecretValue(ctx, secrets, identity.PathLLMKey)
		if err != nil {
			return nil, nil, "", fmt.Errorf("reading LLM API key from Vault: %w", err)
		}
	}

	endpointFn := func() string {
		return configServer.GetConfig(ctx).LLM.Endpoint
	}

	client := gateway.NewClient(endpointFn, apiKey, cfg.LLM.Timeout, meter, budgetEnforcer, alertDispatcher)
	log.Info("LLM gateway client configured", "endpoint", cfg.LLM.Endpoint, "auth", apiKey != "", "live_reload", true)
	return client, meter, apiKey, nil
}
