-- Kernel Guardian / NDIS health and flow telemetry (Phase 12-L)

CREATE TABLE IF NOT EXISTS kernel_snapshots (
    id TEXT PRIMARY KEY NOT NULL,
    device_id TEXT NOT NULL REFERENCES devices(id),
    guardian_mode TEXT NOT NULL DEFAULT 'userspace',
    driver_connected INTEGER NOT NULL DEFAULT 0,
    lifecycle_state TEXT NOT NULL DEFAULT 'stopped',
    kill_switch_mode TEXT,
    stub_mode INTEGER NOT NULL DEFAULT 0,
    wfp_engine TEXT NOT NULL DEFAULT 'userspace',
    ndis_enabled INTEGER NOT NULL DEFAULT 0,
    healthy INTEGER NOT NULL DEFAULT 0,
    filter_count INTEGER NOT NULL DEFAULT 0,
    callouts_registered INTEGER NOT NULL DEFAULT 0,
    transform_profile TEXT,
    cover_traffic_profile TEXT,
    telemetry_json TEXT,
    active_route_count INTEGER NOT NULL DEFAULT 0,
    reported_at TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS kernel_flow_stats (
    id TEXT PRIMARY KEY NOT NULL,
    device_id TEXT NOT NULL REFERENCES devices(id),
    stat_type TEXT NOT NULL DEFAULT 'flow',
    flow_id TEXT NOT NULL,
    process_id INTEGER,
    protocol INTEGER,
    bytes INTEGER NOT NULL DEFAULT 0,
    direction TEXT,
    route_kind TEXT,
    profile_id INTEGER,
    label TEXT,
    active INTEGER NOT NULL DEFAULT 1,
    last_seen_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(device_id, stat_type, flow_id)
);

CREATE INDEX IF NOT EXISTS idx_kernel_snapshots_device ON kernel_snapshots(device_id);
CREATE INDEX IF NOT EXISTS idx_kernel_snapshots_reported ON kernel_snapshots(reported_at);
CREATE INDEX IF NOT EXISTS idx_kernel_flow_stats_device ON kernel_flow_stats(device_id);
CREATE INDEX IF NOT EXISTS idx_kernel_flow_stats_type ON kernel_flow_stats(stat_type);
CREATE INDEX IF NOT EXISTS idx_kernel_flow_stats_active ON kernel_flow_stats(active);
