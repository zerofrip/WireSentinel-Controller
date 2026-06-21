-- Mixnet inventory and health (Phase 10-I)

CREATE TABLE IF NOT EXISTS mixnet_nodes (
    id TEXT PRIMARY KEY NOT NULL,
    device_id TEXT NOT NULL REFERENCES devices(id),
    node_id TEXT NOT NULL,
    gateway_id TEXT NOT NULL,
    country TEXT,
    latency_ms INTEGER,
    healthy INTEGER NOT NULL DEFAULT 0,
    last_seen_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(device_id, node_id)
);

CREATE TABLE IF NOT EXISTS mixnet_routes (
    id TEXT PRIMARY KEY NOT NULL,
    device_id TEXT NOT NULL REFERENCES devices(id),
    route_id TEXT NOT NULL,
    label TEXT NOT NULL,
    hops_json TEXT NOT NULL DEFAULT '[]',
    socks_port INTEGER,
    cover_traffic_profile TEXT,
    active INTEGER NOT NULL DEFAULT 0,
    last_seen_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(device_id, route_id)
);

CREATE TABLE IF NOT EXISTS mixnet_health_snapshots (
    id TEXT PRIMARY KEY NOT NULL,
    device_id TEXT NOT NULL REFERENCES devices(id),
    mixnet_connected INTEGER NOT NULL DEFAULT 0,
    stub_mode INTEGER NOT NULL DEFAULT 0,
    healthy INTEGER NOT NULL DEFAULT 0,
    selected_node_json TEXT,
    active_route_count INTEGER NOT NULL DEFAULT 0,
    cover_traffic_profile TEXT,
    reported_at TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_mixnet_nodes_device ON mixnet_nodes(device_id);
CREATE INDEX IF NOT EXISTS idx_mixnet_nodes_gateway ON mixnet_nodes(gateway_id);
CREATE INDEX IF NOT EXISTS idx_mixnet_routes_device ON mixnet_routes(device_id);
CREATE INDEX IF NOT EXISTS idx_mixnet_routes_active ON mixnet_routes(active);
CREATE INDEX IF NOT EXISTS idx_mixnet_health_device ON mixnet_health_snapshots(device_id);
CREATE INDEX IF NOT EXISTS idx_mixnet_health_reported ON mixnet_health_snapshots(reported_at);
