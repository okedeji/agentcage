package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"time"

	"github.com/go-logr/logr"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"google.golang.org/grpc/credentials"

	"github.com/okedeji/agentcage/internal/config"
	"github.com/okedeji/agentcage/internal/metrics"
)

const otelFlushDeadline = 5 * time.Second

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
		} else {
			creds, err := buildOTelTLSCredentials(cfg.Infrastructure.OTel)
			if err != nil {
				return nil, fmt.Errorf("building OTel TLS credentials: %w", err)
			}
			metricOpts = append(metricOpts, otlpmetricgrpc.WithTLSCredentials(creds))
			traceOpts = append(traceOpts, otlptracegrpc.WithTLSCredentials(creds))
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

func buildOTelTLSCredentials(otelCfg *config.OTelConfig) (credentials.TransportCredentials, error) {
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS13}

	if otelCfg.TLS != nil && otelCfg.TLS.CertFile != "" && otelCfg.TLS.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(otelCfg.TLS.CertFile, otelCfg.TLS.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("loading OTel client cert %s: %w", otelCfg.TLS.CertFile, err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}

	if otelCfg.TLS != nil && otelCfg.TLS.CAFile != "" {
		ca, err := os.ReadFile(otelCfg.TLS.CAFile)
		if err != nil {
			return nil, fmt.Errorf("reading OTel CA file %s: %w", otelCfg.TLS.CAFile, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(ca) {
			return nil, fmt.Errorf("OTel CA file %s: no PEM certs found", otelCfg.TLS.CAFile)
		}
		tlsCfg.RootCAs = pool
	}

	return credentials.NewTLS(tlsCfg), nil
}
