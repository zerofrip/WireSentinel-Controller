-- WireSentinel Controller schema (SQLite)

CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY NOT NULL,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('admin', 'operator', 'viewer')),
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS enrollment_tokens (
    id TEXT PRIMARY KEY NOT NULL,
    token_hash TEXT NOT NULL,
    label TEXT,
    created_at TEXT NOT NULL,
    expires_at TEXT,
    revoked_at TEXT
);

CREATE TABLE IF NOT EXISTS devices (
    id TEXT PRIMARY KEY NOT NULL,
    name TEXT NOT NULL,
    hostname TEXT,
    os TEXT,
    agent_version TEXT,
    enrollment_token_id TEXT REFERENCES enrollment_tokens(id),
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'active', 'revoked')),
    last_heartbeat_at TEXT,
    created_at TEXT NOT NULL,
    metadata TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS policies (
    id TEXT PRIMARY KEY NOT NULL,
    name TEXT NOT NULL,
    scope TEXT NOT NULL CHECK (scope IN ('global', 'group', 'device')),
    scope_target TEXT,
    content TEXT NOT NULL,
    version INTEGER NOT NULL DEFAULT 1,
    pushed_at TEXT,
    revoked_at TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_events (
    id TEXT PRIMARY KEY NOT NULL,
    source TEXT NOT NULL,
    actor TEXT,
    action TEXT NOT NULL,
    resource_type TEXT,
    resource_id TEXT,
    details TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_devices_status ON devices(status);
CREATE INDEX IF NOT EXISTS idx_devices_last_heartbeat ON devices(last_heartbeat_at);
CREATE INDEX IF NOT EXISTS idx_policies_scope ON policies(scope, scope_target);
CREATE INDEX IF NOT EXISTS idx_audit_created_at ON audit_events(created_at);
