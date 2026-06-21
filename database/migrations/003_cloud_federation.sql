-- Cloud federation and hosted controller management (Phase 11)

ALTER TABLE devices ADD COLUMN tenant_id TEXT;
ALTER TABLE policies ADD COLUMN tenant_id TEXT;
ALTER TABLE audit_events ADD COLUMN tenant_id TEXT;

CREATE TABLE IF NOT EXISTS federated_registration (
    id TEXT PRIMARY KEY NOT NULL,
    cloud_controller_id TEXT NOT NULL UNIQUE,
    tenant_id TEXT NOT NULL,
    federation_token_hash TEXT NOT NULL,
    cloud_base_url TEXT NOT NULL,
    registered_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS cloud_controller_links (
    id TEXT PRIMARY KEY NOT NULL,
    tenant_id TEXT NOT NULL,
    cloud_base_url TEXT NOT NULL,
    federation_token_hash TEXT NOT NULL,
    registered_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS federation_sync_bundles (
    id TEXT PRIMARY KEY NOT NULL,
    tenant_id TEXT,
    bundle_json TEXT NOT NULL,
    pushed_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_devices_tenant ON devices(tenant_id);
CREATE INDEX IF NOT EXISTS idx_policies_tenant ON policies(tenant_id);
CREATE INDEX IF NOT EXISTS idx_audit_tenant ON audit_events(tenant_id);
CREATE INDEX IF NOT EXISTS idx_cloud_controller_links_tenant ON cloud_controller_links(tenant_id);
CREATE INDEX IF NOT EXISTS idx_federation_sync_tenant ON federation_sync_bundles(tenant_id);
