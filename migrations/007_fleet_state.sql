-- +migrate Up
CREATE TYPE host_pool AS ENUM ('active', 'warm', 'provisioning', 'draining');
CREATE TYPE host_state AS ENUM ('initializing', 'ready', 'busy', 'draining', 'offline');

CREATE TABLE hosts (
    id                TEXT PRIMARY KEY,
    pool              host_pool NOT NULL DEFAULT 'provisioning',
    state             host_state NOT NULL DEFAULT 'initializing',
    cage_slots_total  INTEGER NOT NULL DEFAULT 0,
    cage_slots_used   INTEGER NOT NULL DEFAULT 0,
    vcpus_total       INTEGER NOT NULL DEFAULT 0,
    vcpus_used        INTEGER NOT NULL DEFAULT 0,
    memory_mb_total   INTEGER NOT NULL DEFAULT 0,
    memory_mb_used    INTEGER NOT NULL DEFAULT 0,
    provider          TEXT,
    region            TEXT,
    instance_type     TEXT,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_hosts_pool ON hosts(pool);
CREATE INDEX idx_hosts_state ON hosts(state);

CREATE TABLE capacity_snapshots (
    total_hosts         INTEGER NOT NULL,
    active_hosts        INTEGER NOT NULL,
    warm_hosts          INTEGER NOT NULL,
    provisioning_hosts  INTEGER NOT NULL,
    total_cage_slots    INTEGER NOT NULL,
    used_cage_slots     INTEGER NOT NULL,
    utilization_ratio   DOUBLE PRECISION NOT NULL,
    snapshot_at         TIMESTAMPTZ NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

SELECT create_hypertable('capacity_snapshots', 'snapshot_at');

DO $$ BEGIN
    ALTER TABLE capacity_snapshots SET (
        timescaledb.compress,
        timescaledb.compress_orderby = 'snapshot_at'
    );
    PERFORM add_compression_policy('capacity_snapshots', INTERVAL '30 days');
EXCEPTION WHEN OTHERS THEN
    RAISE NOTICE 'compression not available (apache license), skipping';
END $$;

-- +migrate Down
DO $$ BEGIN
    PERFORM remove_compression_policy('capacity_snapshots', if_exists => true);
EXCEPTION WHEN OTHERS THEN NULL;
END $$;
DROP TABLE IF EXISTS capacity_snapshots;
DROP TABLE IF EXISTS hosts;
DROP TYPE IF EXISTS host_state;
DROP TYPE IF EXISTS host_pool;
