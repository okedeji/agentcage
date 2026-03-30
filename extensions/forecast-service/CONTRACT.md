# Demand Forecast Service — Python

Predicts cage demand using time-series forecasting. Feeds the fleet autoscaler's Layer 3.

## What this service does

- Reads historical cage demand from Postgres at 1-minute resolution
- Trains a Prophet/NeuralProphet model with daily/weekly seasonality
- Publishes a 60-minute demand forecast with confidence intervals every 5 minutes
- Exposes an HTTP API that the Go orchestrator polls via `ForecastSource` interface

## Integration points

### Input: Postgres

Reads from the `demand_history` table (TimescaleDB hypertable). Schema in `migrations/008_demand_history.sql`.

```sql
SELECT cage_type, requested_count, active_count, queued_count, measured_at
FROM demand_history
WHERE measured_at > NOW() - INTERVAL '7 days'
ORDER BY measured_at;
```

### Output: HTTP API

The orchestrator's `ForecastIntegration` (in `internal/fleet/forecast.go`) polls this endpoint.

```
GET /forecast
```

Response:

```json
{
  "generated_at": "2026-03-28T14:00:00Z",
  "predictions": [
    {"time": "2026-03-28T14:05:00Z", "p50": 620, "p80": 710, "p95": 820},
    {"time": "2026-03-28T14:10:00Z", "p50": 680, "p80": 790, "p95": 930},
    {"time": "2026-03-28T14:30:00Z", "p50": 820, "p80": 950, "p95": 1100},
    {"time": "2026-03-28T15:00:00Z", "p50": 600, "p80": 700, "p95": 810}
  ]
}
```

The autoscaler uses the +10m p80 prediction for scale-up and the +60m p50 for scale-down.

## Tech stack

- Python 3.11+
- Prophet or NeuralProphet for forecasting
- FastAPI for the HTTP API
- psycopg2 for Postgres access

## Build

```
cd services/forecast-service
pip install -r requirements.txt
python src/server.py
```
