-- Anonymity health, routes, and analytics rollups (Phase 13-L)

CREATE TABLE IF NOT EXISTS anonymity_snapshots (
    id TEXT PRIMARY KEY NOT NULL,
    device_id TEXT NOT NULL REFERENCES devices(id),
    anonymity_connected INTEGER NOT NULL DEFAULT 0,
    stub_mode INTEGER NOT NULL DEFAULT 0,
    healthy INTEGER NOT NULL DEFAULT 0,
    anonymity_score INTEGER NOT NULL DEFAULT 0,
    route_entropy REAL NOT NULL DEFAULT 0,
    path_diversity REAL NOT NULL DEFAULT 0,
    cover_traffic_effectiveness REAL NOT NULL DEFAULT 0,
    federation_peer_count INTEGER NOT NULL DEFAULT 0,
    entropy_bits REAL NOT NULL DEFAULT 0,
    active_route_count INTEGER NOT NULL DEFAULT 0,
    federation_json TEXT,
    reported_at TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS anonymity_routes (
    id TEXT PRIMARY KEY NOT NULL,
    device_id TEXT NOT NULL REFERENCES devices(id),
    route_id TEXT NOT NULL,
    label TEXT NOT NULL,
    hops_json TEXT NOT NULL DEFAULT '[]',
    chain_kind TEXT,
    entropy_score REAL,
    active INTEGER NOT NULL DEFAULT 0,
    last_seen_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(device_id, route_id)
);

CREATE TABLE IF NOT EXISTS anonymity_analytics_rollups (
    id TEXT PRIMARY KEY NOT NULL,
    devices_reporting INTEGER NOT NULL DEFAULT 0,
    avg_anonymity_score REAL NOT NULL DEFAULT 0,
    avg_route_entropy REAL NOT NULL DEFAULT 0,
    avg_path_diversity REAL NOT NULL DEFAULT 0,
    avg_cover_traffic_effectiveness REAL NOT NULL DEFAULT 0,
    federation_peers_total INTEGER NOT NULL DEFAULT 0,
    avg_entropy_bits REAL NOT NULL DEFAULT 0,
    rollup_json TEXT NOT NULL DEFAULT '{}',
    rolled_up_at TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_anonymity_snapshots_device ON anonymity_snapshots(device_id);
CREATE INDEX IF NOT EXISTS idx_anonymity_snapshots_reported ON anonymity_snapshots(reported_at);
CREATE INDEX IF NOT EXISTS idx_anonymity_routes_device ON anonymity_routes(device_id);
CREATE INDEX IF NOT EXISTS idx_anonymity_routes_active ON anonymity_routes(active);
CREATE INDEX IF NOT EXISTS idx_anonymity_rollups_rolled_up ON anonymity_analytics_rollups(rolled_up_at);
