CREATE DATABASE IF NOT EXISTS identityguard;

CREATE TABLE IF NOT EXISTS identityguard.events
(
    event_id String,
    account_id LowCardinality(String),
    identity_id String,
    event_time DateTime64(3, 'UTC'),
    event_name LowCardinality(String),
    event_source LowCardinality(String),
    event_category LowCardinality(String),
    aws_region LowCardinality(String)
)
ENGINE = ReplacingMergeTree
PARTITION BY toYYYYMM(event_time)
ORDER BY (account_id, event_time, event_id)
TTL toDateTime(event_time) + INTERVAL 13 MONTH;
