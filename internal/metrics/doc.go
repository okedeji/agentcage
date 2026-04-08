// Package metrics owns the orchestrator's OpenTelemetry instruments
// and the OTel SDK setup. Init registers every counter, histogram,
// and gauge agentcage emits; Setup wires them to an OTLP exporter
// when external OTel is configured. The Temporal metrics handler
// bridges the SDK's internal metrics into the same pipeline so worker
// task slots, poll latency, and workflow task failures land alongside
// agentcage's own metrics.
package metrics
