-- +migrate Up
CREATE TABLE cost_records (
    id              TEXT PRIMARY KEY,
    cage_id         TEXT NOT NULL REFERENCES cages(id),
    assessment_id   TEXT NOT NULL REFERENCES assessments(id),
    compute_cost_usd  NUMERIC(10, 6) NOT NULL DEFAULT 0,
    token_cost_usd    NUMERIC(10, 6) NOT NULL DEFAULT 0,
    total_cost_usd    NUMERIC(10, 6) NOT NULL DEFAULT 0,
    tokens_input    BIGINT NOT NULL DEFAULT 0,
    tokens_output   BIGINT NOT NULL DEFAULT 0,
    provider        TEXT,
    model           TEXT,
    duration_seconds NUMERIC(10, 2),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_cost_records_cage_id ON cost_records(cage_id);
CREATE INDEX idx_cost_records_assessment_id ON cost_records(assessment_id);

-- +migrate Down
DROP TABLE IF EXISTS cost_records;
