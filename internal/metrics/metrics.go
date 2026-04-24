package metrics

import (
	"fmt"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/metric"
)

const meterName = "agentcage"

var (
	CageStartupDuration  metric.Float64Histogram
	CageTeardownDuration metric.Float64Histogram
	CageActiveCount      metric.Int64UpDownCounter

	EgressBlockedTotal  metric.Int64Counter
	PayloadBlockedTotal metric.Int64Counter

	GatewayRequestDuration metric.Float64Histogram
	GatewayTokensConsumed  metric.Int64Counter

	FindingsProcessedTotal metric.Int64Counter

	InterventionResponseDuration metric.Float64Histogram
	InterventionTimeoutTotal     metric.Int64Counter

	FleetHostsActive         metric.Int64UpDownCounter
	FleetCapacityUtilization metric.Float64Gauge

	TripwiresFiredTotal       metric.Int64Counter
	FalcoConnectionFailures   metric.Int64Counter
)

// Init registers all agentcage metric instruments with the global meter provider.
// It must be called after Setup has configured the provider.
func Init() error {
	meter := otel.Meter(meterName)
	var err error

	CageStartupDuration, err = meter.Float64Histogram(
		"agentcage_cage_startup_duration_seconds",
		metric.WithDescription("Time from cage creation request to agent start."),
		metric.WithUnit("s"),
	)
	if err != nil {
		return fmt.Errorf("creating cage startup duration histogram: %w", err)
	}

	CageTeardownDuration, err = meter.Float64Histogram(
		"agentcage_cage_teardown_duration_seconds",
		metric.WithDescription("Time from teardown initiation to full cleanup verification."),
		metric.WithUnit("s"),
	)
	if err != nil {
		return fmt.Errorf("creating cage teardown duration histogram: %w", err)
	}

	CageActiveCount, err = meter.Int64UpDownCounter(
		"agentcage_cage_active_count",
		metric.WithDescription("Number of cages currently running."),
	)
	if err != nil {
		return fmt.Errorf("creating cage active count gauge: %w", err)
	}

	EgressBlockedTotal, err = meter.Int64Counter(
		"agentcage_enforcement_egress_blocked_total",
		metric.WithDescription("Total egress requests blocked by Cilium policy."),
	)
	if err != nil {
		return fmt.Errorf("creating egress blocked counter: %w", err)
	}

	PayloadBlockedTotal, err = meter.Int64Counter(
		"agentcage_enforcement_payload_blocked_total",
		metric.WithDescription("Total payloads blocked by the semantic firewall."),
	)
	if err != nil {
		return fmt.Errorf("creating payload blocked counter: %w", err)
	}

	GatewayRequestDuration, err = meter.Float64Histogram(
		"agentcage_gateway_request_duration_seconds",
		metric.WithDescription("End-to-end latency of LLM gateway proxy requests."),
		metric.WithUnit("s"),
	)
	if err != nil {
		return fmt.Errorf("creating gateway request duration histogram: %w", err)
	}

	GatewayTokensConsumed, err = meter.Int64Counter(
		"agentcage_gateway_tokens_consumed_total",
		metric.WithDescription("Total LLM tokens consumed, labeled by provider and model."),
		metric.WithUnit("{token}"),
	)
	if err != nil {
		return fmt.Errorf("creating gateway tokens consumed counter: %w", err)
	}

	FindingsProcessedTotal, err = meter.Int64Counter(
		"agentcage_findings_processed_total",
		metric.WithDescription("Total findings processed, labeled by type (candidate, validated, rejected)."),
	)
	if err != nil {
		return fmt.Errorf("creating findings processed counter: %w", err)
	}

	InterventionResponseDuration, err = meter.Float64Histogram(
		"agentcage_intervention_response_duration_seconds",
		metric.WithDescription("Time from intervention request to operator decision."),
		metric.WithUnit("s"),
	)
	if err != nil {
		return fmt.Errorf("creating intervention response duration histogram: %w", err)
	}

	InterventionTimeoutTotal, err = meter.Int64Counter(
		"agentcage_intervention_timeout_total",
		metric.WithDescription("Total interventions that timed out without an operator response."),
	)
	if err != nil {
		return fmt.Errorf("creating intervention timeout counter: %w", err)
	}

	FleetHostsActive, err = meter.Int64UpDownCounter(
		"agentcage_fleet_hosts_active",
		metric.WithDescription("Number of active bare-metal hosts, labeled by pool (active, warm, provisioning)."),
	)
	if err != nil {
		return fmt.Errorf("creating fleet hosts active gauge: %w", err)
	}

	FleetCapacityUtilization, err = meter.Float64Gauge(
		"agentcage_fleet_capacity_utilization_ratio",
		metric.WithDescription("Ratio of allocated cage slots to total available slots across the fleet."),
	)
	if err != nil {
		return fmt.Errorf("creating fleet capacity utilization gauge: %w", err)
	}

	TripwiresFiredTotal, err = meter.Int64Counter(
		"agentcage_tripwires_fired_total",
		metric.WithDescription("Total Falco tripwire alerts fired, labeled by rule and action."),
	)
	if err != nil {
		return fmt.Errorf("creating tripwires fired counter: %w", err)
	}

	FalcoConnectionFailures, err = meter.Int64Counter(
		"agentcage_falco_connection_failures_total",
		metric.WithDescription("Total Falco connection failures during cage monitoring."),
	)
	if err != nil {
		return fmt.Errorf("creating falco connection failures counter: %w", err)
	}

	return nil
}
