-- Phase 16 SSE controller integration (16-K)

CREATE TABLE IF NOT EXISTS sse_policies (
    id TEXT PRIMARY KEY NOT NULL,
    name TEXT NOT NULL,
    policy_kind TEXT NOT NULL DEFAULT 'swg',
    enabled INTEGER NOT NULL DEFAULT 1,
    rules_json TEXT NOT NULL DEFAULT '[]',
    default_action TEXT NOT NULL DEFAULT 'allow',
    content_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sse_incidents (
    id TEXT PRIMARY KEY NOT NULL,
    device_id TEXT NOT NULL REFERENCES devices(id),
    incident_kind TEXT NOT NULL CHECK (incident_kind IN ('casb', 'dlp')),
    severity TEXT NOT NULL DEFAULT 'medium',
    title TEXT NOT NULL,
    description TEXT,
    resource TEXT,
    action_taken TEXT NOT NULL DEFAULT 'blocked',
    status TEXT NOT NULL DEFAULT 'open',
    details_json TEXT NOT NULL DEFAULT '{}',
    detected_at TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sse_threat_matches (
    id TEXT PRIMARY KEY NOT NULL,
    device_id TEXT NOT NULL REFERENCES devices(id),
    threat_kind TEXT NOT NULL DEFAULT 'malware',
    category TEXT NOT NULL DEFAULT 'web',
    url TEXT,
    signature TEXT,
    severity TEXT NOT NULL DEFAULT 'medium',
    action TEXT NOT NULL DEFAULT 'blocked',
    matched_at TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sse_risk_scores (
    id TEXT PRIMARY KEY NOT NULL,
    device_id TEXT NOT NULL REFERENCES devices(id),
    risk_score INTEGER NOT NULL DEFAULT 50,
    risk_level TEXT NOT NULL DEFAULT 'medium',
    factors_json TEXT NOT NULL DEFAULT '{}',
    evaluated_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(device_id)
);

CREATE TABLE IF NOT EXISTS sse_ueba_anomalies (
    id TEXT PRIMARY KEY NOT NULL,
    device_id TEXT NOT NULL REFERENCES devices(id),
    user_id TEXT,
    anomaly_kind TEXT NOT NULL DEFAULT 'behavior',
    score REAL NOT NULL DEFAULT 0,
    description TEXT NOT NULL,
    details_json TEXT NOT NULL DEFAULT '{}',
    detected_at TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sse_telemetry_snapshots (
    id TEXT PRIMARY KEY NOT NULL,
    device_id TEXT NOT NULL REFERENCES devices(id),
    swg_requests INTEGER NOT NULL DEFAULT 0,
    swg_blocked INTEGER NOT NULL DEFAULT 0,
    swg_allowed INTEGER NOT NULL DEFAULT 0,
    threat_count INTEGER NOT NULL DEFAULT 0,
    casb_incidents INTEGER NOT NULL DEFAULT 0,
    dlp_incidents INTEGER NOT NULL DEFAULT 0,
    risk_score INTEGER NOT NULL DEFAULT 0,
    ueba_alerts INTEGER NOT NULL DEFAULT 0,
    reported_at TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_sse_incidents_kind ON sse_incidents(incident_kind);
CREATE INDEX IF NOT EXISTS idx_sse_incidents_device ON sse_incidents(device_id);
CREATE INDEX IF NOT EXISTS idx_sse_threat_matches_device ON sse_threat_matches(device_id);
CREATE INDEX IF NOT EXISTS idx_sse_risk_scores_device ON sse_risk_scores(device_id);
CREATE INDEX IF NOT EXISTS idx_sse_ueba_device ON sse_ueba_anomalies(device_id);
CREATE INDEX IF NOT EXISTS idx_sse_telemetry_device ON sse_telemetry_snapshots(device_id);
CREATE INDEX IF NOT EXISTS idx_sse_telemetry_reported ON sse_telemetry_snapshots(reported_at);
