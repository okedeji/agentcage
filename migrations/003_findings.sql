-- +migrate Up
CREATE TYPE finding_status AS ENUM ('candidate', 'validated', 'rejected');
CREATE TYPE finding_severity AS ENUM ('info', 'low', 'medium', 'high', 'critical');

CREATE TABLE findings (
    id                TEXT PRIMARY KEY,
    assessment_id     TEXT NOT NULL REFERENCES assessments(id),
    cage_id           TEXT NOT NULL REFERENCES cages(id),
    status            finding_status NOT NULL DEFAULT 'candidate',
    severity          finding_severity NOT NULL,
    title             TEXT NOT NULL,
    description       TEXT,
    vuln_class        TEXT NOT NULL,
    endpoint          TEXT,
    evidence          JSONB,
    parent_finding_id TEXT REFERENCES findings(id),
    chain_depth       INTEGER NOT NULL DEFAULT 0,
    validated_at      TIMESTAMPTZ,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_findings_assessment_id ON findings(assessment_id);
CREATE INDEX idx_findings_assessment_status_created ON findings(assessment_id, status, created_at DESC);
CREATE INDEX idx_findings_cage_id ON findings(cage_id);
CREATE INDEX idx_findings_status ON findings(status);
CREATE INDEX idx_findings_vuln_class ON findings(vuln_class);

-- +migrate Down
DROP TABLE IF EXISTS findings;
DROP TYPE IF EXISTS finding_severity;
DROP TYPE IF EXISTS finding_status;
