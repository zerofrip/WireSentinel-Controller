-- Phase 15 ZTNA controller integration (15-L)

CREATE TABLE IF NOT EXISTS ztna_policies (
    id TEXT PRIMARY KEY NOT NULL,
    name TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    min_trust_level TEXT NOT NULL DEFAULT 'medium',
    min_trust_score INTEGER NOT NULL DEFAULT 50,
    conditions_json TEXT NOT NULL DEFAULT '[]',
    default_action TEXT NOT NULL DEFAULT 'deny',
    content_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS published_resources (
    id TEXT PRIMARY KEY NOT NULL,
    name TEXT NOT NULL,
    resource_type TEXT NOT NULL DEFAULT 'https',
    host TEXT NOT NULL,
    port INTEGER NOT NULL DEFAULT 443,
    path_prefix TEXT,
    tags_json TEXT NOT NULL DEFAULT '[]',
    published INTEGER NOT NULL DEFAULT 0,
    access_policy_id TEXT,
    published_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS device_trust (
    id TEXT PRIMARY KEY NOT NULL,
    device_id TEXT NOT NULL REFERENCES devices(id),
    trust_level TEXT NOT NULL DEFAULT 'medium',
    trust_score INTEGER NOT NULL DEFAULT 50,
    posture_json TEXT NOT NULL DEFAULT '{}',
    certificate_fingerprint TEXT,
    last_evaluated_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(device_id)
);

CREATE TABLE IF NOT EXISTS ztna_heartbeats (
    id TEXT PRIMARY KEY NOT NULL,
    device_id TEXT NOT NULL REFERENCES devices(id),
    identity_connected INTEGER NOT NULL DEFAULT 0,
    active_provider TEXT,
    gateway_active INTEGER NOT NULL DEFAULT 0,
    connector_count INTEGER NOT NULL DEFAULT 0,
    healthy_connectors INTEGER NOT NULL DEFAULT 0,
    avg_trust_score REAL NOT NULL DEFAULT 0,
    published_resource_count INTEGER NOT NULL DEFAULT 0,
    recent_denials INTEGER NOT NULL DEFAULT 0,
    reported_at TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS connectors (
    id TEXT PRIMARY KEY NOT NULL,
    device_id TEXT NOT NULL REFERENCES devices(id),
    connector_id TEXT NOT NULL,
    name TEXT NOT NULL,
    endpoint TEXT NOT NULL,
    resource_ids_json TEXT NOT NULL DEFAULT '[]',
    healthy INTEGER NOT NULL DEFAULT 1,
    latency_ms INTEGER,
    last_seen_at TEXT NOT NULL,
    registered_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(device_id, connector_id)
);

CREATE INDEX IF NOT EXISTS idx_ztna_heartbeats_device ON ztna_heartbeats(device_id);
CREATE INDEX IF NOT EXISTS idx_ztna_heartbeats_reported ON ztna_heartbeats(reported_at);
CREATE INDEX IF NOT EXISTS idx_device_trust_device ON device_trust(device_id);
CREATE INDEX IF NOT EXISTS idx_connectors_device ON connectors(device_id);
CREATE INDEX IF NOT EXISTS idx_published_resources_published ON published_resources(published);
