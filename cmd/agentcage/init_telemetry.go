package main

import (
	"context"
	"fmt"
	"time"

	"github.com/go-logr/logr"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"

	"github.com/okedeji/agentcage/internal/config"
	"github.com/okedeji/agentcage/internal/metrics"
)

// A wedged exporter can't block exit.
const otelFlushDeadline = 5 * time.Second

// metrics.Init always runs so the in-process registry is live even
// in dev mode without an exporter.
func setupTelemetry(ctx context.Context, cfg *config.Config, log logr.Logger) (func(), error) {
	fmt.Println("Initializing telemetry...")

	shutdown := func() {} // no-op default

	if cfg.Infrastructure.IsExternalOTel() {
		metricOpts := []otlpmetricgrpc.Option{
			otlpmetricgrpc.WithEndpointURL(cfg.Infrastructure.OTel.Endpoint),
		}
		traceOpts := []otlptracegrpc.Option{
			otlptracegrpc.WithEndpointURL(cfg.Infrastructure.OTel.Endpoint),
		}
		if cfg.OTelInsecureDefault() {
			metricOpts = append(metricOpts, otlpmetricgrpc.WithInsecure())
			traceOpts = append(traceOpts, otlptracegrpc.WithInsecure())
		}
		metricExp, metricErr := otlpmetricgrpc.New(ctx, metricOpts...)
		if metricErr != nil {
			return nil, fmt.Errorf("creating OTLP metric exporter: %w", metricErr)
		}
		traceExp, traceErr := otlptracegrpc.New(ctx, traceOpts...)
		if traceErr != nil {
			return nil, fmt.Errorf("creating OTLP trace exporter: %w", traceErr)
		}
		otelShutdown, setupErr := metrics.Setup(ctx, metricExp, traceExp)
		if setupErr != nil {
			return nil, fmt.Errorf("setting up OTel providers: %w", setupErr)
		}
		shutdown = func() {
			shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), otelFlushDeadline)
			defer shutdownCancel()
			if err := otelShutdown(shutdownCtx); err != nil {
				log.Error(err, "flushing OTel providers")
			}
		}
		log.Info("OTel telemetry enabled", "endpoint", cfg.Infrastructure.OTel.Endpoint)
	}

	if err := metrics.Init(); err != nil {
		return nil, fmt.Errorf("initializing metrics: %w", err)
	}
	return shutdown, nil
}
