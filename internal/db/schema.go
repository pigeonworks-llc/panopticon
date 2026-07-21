package db

// Schema DDL for the Panopticon SQLite database.
const Schema = `
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

-- CA certificate (one row, created on first run)
CREATE TABLE IF NOT EXISTS ca_cert (
    id         INTEGER PRIMARY KEY,
    cert_pem   TEXT    NOT NULL,
    key_pem    TEXT    NOT NULL,
    created_at TEXT    NOT NULL DEFAULT (datetime('now')),
    expires_at TEXT    NOT NULL
);

-- Per-host certificates cache
CREATE TABLE IF NOT EXISTS host_certs (
    host       TEXT    PRIMARY KEY,
    cert_pem   TEXT    NOT NULL,
    key_pem    TEXT    NOT NULL,
    issued_at  TEXT    NOT NULL,
    expires_at TEXT    NOT NULL,
    ttl_seconds INTEGER NOT NULL DEFAULT 86400
);

-- Rules
CREATE TABLE IF NOT EXISTS rules (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT    NOT NULL,
    priority    INTEGER NOT NULL DEFAULT 100,
    enabled     INTEGER NOT NULL DEFAULT 1,
    conditions  TEXT    NOT NULL,
    action      TEXT    NOT NULL,
    created_at  TEXT    NOT NULL DEFAULT (datetime('now')),
    updated_at  TEXT    NOT NULL DEFAULT (datetime('now')),
    notes       TEXT
);

-- Rule application log
CREATE TABLE IF NOT EXISTS rule_applications (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id    INTEGER REFERENCES rules(id),
    host       TEXT    NOT NULL,
    path       TEXT    NOT NULL,
    action     TEXT    NOT NULL,
    process_id TEXT,
    ts         TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- Captured request summaries
CREATE TABLE IF NOT EXISTS captured_requests (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    request_id    TEXT    NOT NULL UNIQUE,
    host          TEXT    NOT NULL,
    path          TEXT    NOT NULL,
    method        TEXT    NOT NULL,
    status_code   INTEGER,
    content_type  TEXT,
    request_size  INTEGER,
    response_size INTEGER,
    duration_ms   INTEGER,
    process_id    TEXT,
    rule_id       INTEGER REFERENCES rules(id),
    body_path     TEXT,
    ts            TEXT    NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_captured_requests_host ON captured_requests(host);
CREATE INDEX IF NOT EXISTS idx_captured_requests_ts  ON captured_requests(ts);

-- Process identity cache (macOS PID → bundle_id)
CREATE TABLE IF NOT EXISTS process_identity_cache (
    pid            INTEGER PRIMARY KEY,
    bundle_id      TEXT    NOT NULL,
    process_name   TEXT,
    executable_path TEXT,
    updated_at     TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- Events (events_v2 compatible)
CREATE TABLE IF NOT EXISTS events (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id     TEXT    NOT NULL UNIQUE,
    event_name   TEXT    NOT NULL,
    schema_ver   INTEGER NOT NULL DEFAULT 1,
    ts           TEXT    NOT NULL,
    service      TEXT    NOT NULL DEFAULT 'panopticon',
    severity     TEXT    NOT NULL DEFAULT 'info',
    trace_id     TEXT,
    span_id      TEXT,
    causation_id TEXT,
    payload      TEXT
);

-- Plugin registry
CREATE TABLE IF NOT EXISTS plugin_registry (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT    NOT NULL UNIQUE,
    path       TEXT    NOT NULL,
    version    TEXT,
    enabled    INTEGER NOT NULL DEFAULT 1,
    hook_point TEXT    NOT NULL,
    loaded_at  TEXT,
    created_at TEXT    NOT NULL DEFAULT (datetime('now'))
);
`
