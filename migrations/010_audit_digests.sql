-- +migrate Up
CREATE TABLE audit_digests (
    assessment_id   TEXT NOT NULL REFERENCES assessments(id),
    cage_id         TEXT NOT NULL,
    chain_head_hash BYTEA NOT NULL,
    entry_count     BIGINT NOT NULL,
    key_version     TEXT NOT NULL,
    signature       BYTEA NOT NULL,
    issued_at       TIMESTAMPTZ NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(cage_id, issued_at)
);

CREATE INDEX idx_audit_digests_cage_id ON audit_digests(cage_id);
CREATE INDEX idx_audit_digests_assessment_id ON audit_digests(assessment_id);

-- +migrate Down
DROP TABLE IF EXISTS audit_digests;
