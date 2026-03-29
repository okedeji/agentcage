-- +migrate Up
CREATE EXTENSION IF NOT EXISTS timescaledb;

-- +migrate Down
DROP EXTENSION IF EXISTS timescaledb;
