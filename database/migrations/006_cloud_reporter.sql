-- Phase 14-M/N: cloud ingress buffers and federation outbound token

ALTER TABLE federated_registration ADD COLUMN outbound_federation_token TEXT;

CREATE TABLE IF NOT EXISTS cloud_usage_ingress (
    id TEXT PRIMARY KEY NOT NULL,
    tenant_id TEXT,
    device_id TEXT,
    payload_json TEXT NOT NULL,
    received_at TEXT NOT NULL,
    forwarded_at TEXT
);

CREATE TABLE IF NOT EXISTS cloud_health_ingress (
    id TEXT PRIMARY KEY NOT NULL,
    tenant_id TEXT,
    payload_json TEXT NOT NULL,
    received_at TEXT NOT NULL,
    forwarded_at TEXT
);

CREATE TABLE IF NOT EXISTS cloud_logs_ingress (
    id TEXT PRIMARY KEY NOT NULL,
    tenant_id TEXT,
    device_id TEXT,
    payload_json TEXT NOT NULL,
    received_at TEXT NOT NULL,
    forwarded_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_cloud_usage_ingress_forwarded ON cloud_usage_ingress(forwarded_at);
CREATE INDEX IF NOT EXISTS idx_cloud_health_ingress_forwarded ON cloud_health_ingress(forwarded_at);
CREATE INDEX IF NOT EXISTS idx_cloud_logs_ingress_forwarded ON cloud_logs_ingress(forwarded_at);
