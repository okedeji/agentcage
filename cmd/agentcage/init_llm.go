package main

import (
	"fmt"
	"os"

	"github.com/go-logr/logr"

	"github.com/okedeji/agentcage/internal/alert"
	"github.com/okedeji/agentcage/internal/config"
	"github.com/okedeji/agentcage/internal/gateway"
)

// Without an LLM endpoint the assessment coordinator can't plan
// cages, but discovery and validator workflows still run.
func buildLLMClient(cfg *config.Config, alertDispatcher *alert.Dispatcher, log logr.Logger) (*gateway.Client, error) {
	meter := gateway.NewTokenMeter()
	budgetEnforcer := gateway.NewBudgetEnforcer(meter)

	if cfg.LLM.Endpoint == "" {
		if cfg.LLMRequiredDefault() {
			return nil, fmt.Errorf("posture=strict: llm.endpoint is required (the assessment coordinator and discovery cages cannot run without an LLM)")
		}
		log.Info("WARNING: no LLM endpoint configured. Assessment coordinator will not be able to plan cages.")
		return nil, nil
	}

	var apiKey string
	if cfg.LLM.APIKeyEnv != "" {
		apiKey = os.Getenv(cfg.LLM.APIKeyEnv)
		if apiKey == "" {
			return nil, fmt.Errorf("LLM API key env var %s is not set", cfg.LLM.APIKeyEnv)
		}
	}
	client := gateway.NewClient(cfg.LLM.Endpoint, apiKey, cfg.LLM.Timeout, meter, budgetEnforcer, alertDispatcher)
	log.Info("LLM gateway client configured", "endpoint", cfg.LLM.Endpoint, "auth", apiKey != "")
	return client, nil
}
