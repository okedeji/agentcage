-- +migrate Up
CREATE TABLE slo_metrics (
    id              BIGSERIAL NOT NULL,
    indicator       TEXT NOT NULL,
    value           DOUBLE PRECISION NOT NULL,
    target          DOUBLE PRECISION NOT NULL,
    good            BOOLEAN NOT NULL,
    measured_at     TIMESTAMPTZ NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

SELECT create_hypertable('slo_metrics', 'measured_at');

CREATE INDEX idx_slo_metrics_indicator ON slo_metrics(indicator, measured_at DESC);

DO $$ BEGIN
    ALTER TABLE slo_metrics SET (
        timescaledb.compress,
        timescaledb.compress_segmentby = 'indicator',
        timescaledb.compress_orderby = 'measured_at'
    );
    PERFORM add_compression_policy('slo_metrics', INTERVAL '30 days');
EXCEPTION WHEN OTHERS THEN
    RAISE NOTICE 'compression not available (apache license), skipping';
END $$;

-- +migrate Down
DO $$ BEGIN
    PERFORM remove_compression_policy('slo_metrics', if_exists => true);
EXCEPTION WHEN OTHERS THEN NULL;
END $$;
DROP TABLE IF EXISTS slo_metrics;
