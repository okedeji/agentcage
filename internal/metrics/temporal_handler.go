package metrics

import (
	"context"
	"sync"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"go.temporal.io/sdk/client"
)

// NewTemporalMetricsHandler returns a client.MetricsHandler implementation
// that emits Temporal SDK metrics through the global OTel meter provider,
// so worker internals (task slot availability, workflow task failures,
// poll latency) flow into the same OTel pipeline as the rest of agentcage.
//
// Counters and timers are looked up lazily on first use and cached. Tags
// from the SDK become OTel attributes on each emission.
func NewTemporalMetricsHandler() client.MetricsHandler {
	return &temporalHandler{
		meter: otel.Meter("agentcage_temporal"),
		tags:  nil,
	}
}

type temporalHandler struct {
	meter   metric.Meter
	tags    map[string]string
	counter sync.Map // name → metric.Int64Counter
	gauge   sync.Map // name → metric.Float64Gauge
	timer   sync.Map // name → metric.Float64Histogram
}

func (h *temporalHandler) WithTags(tags map[string]string) client.MetricsHandler {
	merged := make(map[string]string, len(h.tags)+len(tags))
	for k, v := range h.tags {
		merged[k] = v
	}
	for k, v := range tags {
		merged[k] = v
	}
	return &temporalHandler{
		meter: h.meter,
		tags:  merged,
	}
}

func (h *temporalHandler) Counter(name string) client.MetricsCounter {
	if v, ok := h.counter.Load(name); ok {
		return &otelCounter{c: v.(metric.Int64Counter), attrs: h.attrs()}
	}
	c, err := h.meter.Int64Counter(name)
	if err != nil {
		return noopCounter{}
	}
	h.counter.Store(name, c)
	return &otelCounter{c: c, attrs: h.attrs()}
}

func (h *temporalHandler) Gauge(name string) client.MetricsGauge {
	if v, ok := h.gauge.Load(name); ok {
		return &otelGauge{g: v.(metric.Float64Gauge), attrs: h.attrs()}
	}
	g, err := h.meter.Float64Gauge(name)
	if err != nil {
		return noopGauge{}
	}
	h.gauge.Store(name, g)
	return &otelGauge{g: g, attrs: h.attrs()}
}

func (h *temporalHandler) Timer(name string) client.MetricsTimer {
	if v, ok := h.timer.Load(name); ok {
		return &otelTimer{t: v.(metric.Float64Histogram), attrs: h.attrs()}
	}
	t, err := h.meter.Float64Histogram(name)
	if err != nil {
		return noopTimer{}
	}
	h.timer.Store(name, t)
	return &otelTimer{t: t, attrs: h.attrs()}
}

func (h *temporalHandler) attrs() []attribute.KeyValue {
	out := make([]attribute.KeyValue, 0, len(h.tags))
	for k, v := range h.tags {
		out = append(out, attribute.String(k, v))
	}
	return out
}

type otelCounter struct {
	c     metric.Int64Counter
	attrs []attribute.KeyValue
}

func (c *otelCounter) Inc(delta int64) {
	c.c.Add(context.Background(), delta, metric.WithAttributes(c.attrs...))
}

type otelGauge struct {
	g     metric.Float64Gauge
	attrs []attribute.KeyValue
}

func (g *otelGauge) Update(value float64) {
	g.g.Record(context.Background(), value, metric.WithAttributes(g.attrs...))
}

type otelTimer struct {
	t     metric.Float64Histogram
	attrs []attribute.KeyValue
}

func (t *otelTimer) Record(d time.Duration) {
	t.t.Record(context.Background(), d.Seconds(), metric.WithAttributes(t.attrs...))
}

// noop fallbacks used when instrument creation fails. Extremely
// rare; only happens on duplicate registration with conflicting types.

type noopCounter struct{}

func (noopCounter) Inc(int64) {}

type noopGauge struct{}

func (noopGauge) Update(float64) {}

type noopTimer struct{}

func (noopTimer) Record(time.Duration) {}
