-- +migrate Up
CREATE TABLE audit_entries (
    id              TEXT NOT NULL,
    cage_id         TEXT NOT NULL,
    assessment_id   TEXT NOT NULL,
    sequence        BIGINT NOT NULL,
    entry_type      TEXT NOT NULL,
    timestamp       TIMESTAMPTZ NOT NULL,
    data            JSONB,
    key_version     TEXT NOT NULL,
    signature       BYTEA NOT NULL,
    previous_hash   BYTEA NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Convert to TimescaleDB hypertable partitioned by timestamp.
-- Append-only, high-volume, time-ordered — exactly the workload
-- hypertables are designed for. Old chunks compress automatically.
SELECT create_hypertable('audit_entries', 'timestamp');

-- Chain verification reads all entries for a cage in sequence order.
CREATE UNIQUE INDEX idx_audit_entries_cage_sequence ON audit_entries(cage_id, sequence);
CREATE INDEX idx_audit_entries_id ON audit_entries(id);
CREATE INDEX idx_audit_entries_assessment_id ON audit_entries(assessment_id);
CREATE INDEX idx_audit_entries_entry_type ON audit_entries(entry_type);

-- Compress chunks older than 7 days. Compressed data is still queryable.
-- Segmenting by cage_id keeps each cage's chain contiguous in storage,
-- which is critical for chain verification performance.
ALTER TABLE audit_entries SET (
    timescaledb.compress,
    timescaledb.compress_segmentby = 'cage_id',
    timescaledb.compress_orderby = 'sequence'
);
SELECT add_compression_policy('audit_entries', INTERVAL '7 days');

-- +migrate Down
SELECT remove_compression_policy('audit_entries', if_exists => true);
DROP TABLE IF EXISTS audit_entries;
