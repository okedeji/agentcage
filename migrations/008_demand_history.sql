-- +migrate Up
CREATE TABLE demand_history (
    cage_type           TEXT NOT NULL,
    requested_count     INTEGER NOT NULL,
    active_count        INTEGER NOT NULL,
    queued_count        INTEGER NOT NULL DEFAULT 0,
    measured_at         TIMESTAMPTZ NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

SELECT create_hypertable('demand_history', 'measured_at');

CREATE INDEX idx_demand_history_cage_type ON demand_history(cage_type, measured_at DESC);

DO $$ BEGIN
    ALTER TABLE demand_history SET (
        timescaledb.compress,
        timescaledb.compress_segmentby = 'cage_type',
        timescaledb.compress_orderby = 'measured_at'
    );
    PERFORM add_compression_policy('demand_history', INTERVAL '90 days');
EXCEPTION WHEN OTHERS THEN
    RAISE NOTICE 'compression not available (apache license), skipping';
END $$;

-- +migrate Down
DO $$ BEGIN
    PERFORM remove_compression_policy('demand_history', if_exists => true);
EXCEPTION WHEN OTHERS THEN NULL;
END $$;
DROP TABLE IF EXISTS demand_history;
