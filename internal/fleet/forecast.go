package fleet

import (
	"context"
	"fmt"
	"time"

	"github.com/go-logr/logr"
)

type ForecastPoint struct {
	Time time.Time
	P50  int32
	P80  int32
	P95  int32
}

type Forecast struct {
	GeneratedAt time.Time
	Predictions []ForecastPoint
}

type ForecastSource interface {
	GetForecast(ctx context.Context) (*Forecast, error)
}

type WebhookSignal struct {
	CustomerID     string
	AssessmentSize string
	ScheduledAt    time.Time
}

type SignalSource interface {
	GetPendingSignals(ctx context.Context) ([]WebhookSignal, error)
	AcknowledgeSignal(ctx context.Context, signal WebhookSignal) error
}

type ForecastIntegration struct {
	autoscaler   *Autoscaler
	forecast     ForecastSource
	signals      SignalSource
	pollInterval time.Duration
	logger       logr.Logger
}

func NewForecastIntegration(autoscaler *Autoscaler, forecast ForecastSource, signals SignalSource, pollInterval time.Duration, logger logr.Logger) *ForecastIntegration {
	return &ForecastIntegration{
		autoscaler:   autoscaler,
		forecast:     forecast,
		signals:      signals,
		pollInterval: pollInterval,
		logger:       logger,
	}
}

func (f *ForecastIntegration) Run(ctx context.Context) error {
	ticker := time.NewTicker(f.pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			f.reconcile(ctx)
		}
	}
}

func (f *ForecastIntegration) reconcile(ctx context.Context) {
	f.applyForecast(ctx)
	f.applySignals(ctx)
}

func (f *ForecastIntegration) applyForecast(ctx context.Context) {
	fc, err := f.forecast.GetForecast(ctx)
	if err != nil {
		f.logger.Error(err, "fetching forecast")
		return
	}
	if fc == nil || len(fc.Predictions) == 0 {
		return
	}

	prediction := nearestPrediction(fc.Predictions, time.Now().Add(10*time.Minute))
	if prediction == nil {
		return
	}

	demand := prediction.P80
	status := f.autoscaler.pool.GetFleetStatus()
	var available int32
	for _, ps := range status.Pools {
		if ps.Pool == PoolActive || ps.Pool == PoolWarm {
			available += ps.CageSlotsTotal - ps.CageSlotsUsed
		}
	}

	gap := demand - available
	if gap <= 0 {
		return
	}

	slotsPerHost := CalculateSlots(Host{VCPUsTotal: 64, MemoryMBTotal: 131072}, f.autoscaler.config.DefaultCageResources)
	if slotsPerHost <= 0 {
		f.logger.Error(fmt.Errorf("slots per host is zero"), "cannot estimate hosts from forecast")
		return
	}

	hostsNeeded := (gap + slotsPerHost - 1) / slotsPerHost
	f.logger.Info("forecast indicates capacity gap", "predicted_demand", demand, "available", available, "provisioning_hosts", hostsNeeded)

	for range hostsNeeded {
		if ctx.Err() != nil {
			return
		}
		host, err := f.autoscaler.provisioner.Provision(ctx)
		if err != nil {
			f.logger.Error(err, "provisioning host from forecast")
			continue
		}
		if err := f.autoscaler.pool.AddHost(*host); err != nil {
			f.logger.Error(err, "adding forecast-provisioned host to pool", "host_id", host.ID)
		}
	}
}

func (f *ForecastIntegration) applySignals(ctx context.Context) {
	signals, err := f.signals.GetPendingSignals(ctx)
	if err != nil {
		f.logger.Error(err, "fetching webhook signals")
		return
	}

	for _, sig := range signals {
		peak := estimateSignalDemand(sig.AssessmentSize)
		demandKey := fmt.Sprintf("signal:%s:%d", sig.CustomerID, sig.ScheduledAt.Unix())
		if f.autoscaler.demand.GetDemand(demandKey) > 0 {
			continue
		}
		f.autoscaler.demand.AddDemand(demandKey, peak)
		f.logger.V(1).Info("webhook signal applied to demand ledger", "customer_id", sig.CustomerID, "size", sig.AssessmentSize, "peak", peak)

		if err := f.signals.AcknowledgeSignal(ctx, sig); err != nil {
			f.logger.Error(err, "acknowledging webhook signal", "customer_id", sig.CustomerID)
		}
	}
}

func nearestPrediction(predictions []ForecastPoint, target time.Time) *ForecastPoint {
	if len(predictions) == 0 {
		return nil
	}

	best := &predictions[0]
	bestDelta := absDuration(predictions[0].Time.Sub(target))
	for i := 1; i < len(predictions); i++ {
		delta := absDuration(predictions[i].Time.Sub(target))
		if delta < bestDelta {
			best = &predictions[i]
			bestDelta = delta
		}
	}
	return best
}

func absDuration(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}

func estimateSignalDemand(size string) int32 {
	switch size {
	case "small":
		return 150
	case "medium":
		return 500
	case "large":
		return 1500
	default:
		return 500
	}
}
