-- Phase 18 CNAPP controller integration

CREATE TABLE IF NOT EXISTS cnapp_cloud_resources (
    id TEXT PRIMARY KEY NOT NULL,
    device_id TEXT REFERENCES devices(id),
    provider TEXT NOT NULL DEFAULT 'aws',
    resource_type TEXT NOT NULL,
    resource_arn TEXT,
    name TEXT NOT NULL,
    region TEXT,
    account_id TEXT,
    tags_json TEXT NOT NULL DEFAULT '{}',
    risk_score INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'active',
    details_json TEXT NOT NULL DEFAULT '{}',
    discovered_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS cnapp_posture_findings (
    id TEXT PRIMARY KEY NOT NULL,
    device_id TEXT REFERENCES devices(id),
    resource_id TEXT REFERENCES cnapp_cloud_resources(id),
    finding_kind TEXT NOT NULL DEFAULT 'misconfiguration',
    severity TEXT NOT NULL DEFAULT 'medium',
    title TEXT NOT NULL,
    description TEXT,
    status TEXT NOT NULL DEFAULT 'open',
    framework TEXT,
    details_json TEXT NOT NULL DEFAULT '{}',
    detected_at TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS cnapp_risk_scores (
    id TEXT PRIMARY KEY NOT NULL,
    device_id TEXT REFERENCES devices(id),
    scope_kind TEXT NOT NULL DEFAULT 'cloud',
    scope_ref TEXT,
    risk_score INTEGER NOT NULL DEFAULT 50,
    risk_level TEXT NOT NULL DEFAULT 'medium',
    factors_json TEXT NOT NULL DEFAULT '{}',
    evaluated_at TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS cnapp_workloads (
    id TEXT PRIMARY KEY NOT NULL,
    device_id TEXT REFERENCES devices(id),
    workload_kind TEXT NOT NULL DEFAULT 'pod',
    name TEXT NOT NULL,
    namespace TEXT,
    cluster_id TEXT,
    status TEXT NOT NULL DEFAULT 'running',
    image_ref TEXT,
    labels_json TEXT NOT NULL DEFAULT '{}',
    details_json TEXT NOT NULL DEFAULT '{}',
    discovered_at TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS cnapp_workload_threats (
    id TEXT PRIMARY KEY NOT NULL,
    workload_id TEXT REFERENCES cnapp_workloads(id),
    device_id TEXT REFERENCES devices(id),
    threat_kind TEXT NOT NULL DEFAULT 'runtime',
    severity TEXT NOT NULL DEFAULT 'medium',
    title TEXT NOT NULL,
    description TEXT,
    status TEXT NOT NULL DEFAULT 'open',
    details_json TEXT NOT NULL DEFAULT '{}',
    detected_at TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS cnapp_k8s_clusters (
    id TEXT PRIMARY KEY NOT NULL,
    device_id TEXT REFERENCES devices(id),
    name TEXT NOT NULL,
    provider TEXT NOT NULL DEFAULT 'eks',
    version TEXT,
    node_count INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'healthy',
    details_json TEXT NOT NULL DEFAULT '{}',
    discovered_at TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS cnapp_k8s_resources (
    id TEXT PRIMARY KEY NOT NULL,
    cluster_id TEXT NOT NULL REFERENCES cnapp_k8s_clusters(id),
    device_id TEXT REFERENCES devices(id),
    resource_kind TEXT NOT NULL DEFAULT 'deployment',
    namespace TEXT,
    name TEXT NOT NULL,
    uid TEXT,
    labels_json TEXT NOT NULL DEFAULT '{}',
    details_json TEXT NOT NULL DEFAULT '{}',
    discovered_at TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS cnapp_k8s_findings (
    id TEXT PRIMARY KEY NOT NULL,
    cluster_id TEXT REFERENCES cnapp_k8s_clusters(id),
    resource_id TEXT REFERENCES cnapp_k8s_resources(id),
    device_id TEXT REFERENCES devices(id),
    finding_kind TEXT NOT NULL DEFAULT 'policy',
    severity TEXT NOT NULL DEFAULT 'medium',
    title TEXT NOT NULL,
    description TEXT,
    status TEXT NOT NULL DEFAULT 'open',
    details_json TEXT NOT NULL DEFAULT '{}',
    detected_at TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS cnapp_container_images (
    id TEXT PRIMARY KEY NOT NULL,
    device_id TEXT REFERENCES devices(id),
    registry TEXT,
    repository TEXT NOT NULL,
    tag TEXT,
    digest TEXT,
    size_bytes INTEGER,
    scan_status TEXT NOT NULL DEFAULT 'pending',
    details_json TEXT NOT NULL DEFAULT '{}',
    discovered_at TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS cnapp_container_findings (
    id TEXT PRIMARY KEY NOT NULL,
    image_id TEXT REFERENCES cnapp_container_images(id),
    device_id TEXT REFERENCES devices(id),
    finding_kind TEXT NOT NULL DEFAULT 'vulnerability',
    severity TEXT NOT NULL DEFAULT 'medium',
    title TEXT NOT NULL,
    cve_id TEXT,
    package_name TEXT,
    status TEXT NOT NULL DEFAULT 'open',
    details_json TEXT NOT NULL DEFAULT '{}',
    detected_at TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS cnapp_iac_scans (
    id TEXT PRIMARY KEY NOT NULL,
    device_id TEXT REFERENCES devices(id),
    scan_kind TEXT NOT NULL DEFAULT 'terraform',
    repository TEXT,
    branch TEXT,
    commit_sha TEXT,
    status TEXT NOT NULL DEFAULT 'completed',
    finding_count INTEGER NOT NULL DEFAULT 0,
    details_json TEXT NOT NULL DEFAULT '{}',
    scanned_at TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS cnapp_iac_findings (
    id TEXT PRIMARY KEY NOT NULL,
    scan_id TEXT REFERENCES cnapp_iac_scans(id),
    device_id TEXT REFERENCES devices(id),
    finding_kind TEXT NOT NULL DEFAULT 'misconfiguration',
    severity TEXT NOT NULL DEFAULT 'medium',
    title TEXT NOT NULL,
    file_path TEXT,
    line_number INTEGER,
    rule_id TEXT,
    status TEXT NOT NULL DEFAULT 'open',
    details_json TEXT NOT NULL DEFAULT '{}',
    detected_at TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS cnapp_secret_findings (
    id TEXT PRIMARY KEY NOT NULL,
    device_id TEXT REFERENCES devices(id),
    secret_kind TEXT NOT NULL DEFAULT 'api_key',
    severity TEXT NOT NULL DEFAULT 'high',
    source TEXT,
    file_path TEXT,
    redacted_preview TEXT,
    status TEXT NOT NULL DEFAULT 'open',
    details_json TEXT NOT NULL DEFAULT '{}',
    detected_at TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS cnapp_dependencies (
    id TEXT PRIMARY KEY NOT NULL,
    device_id TEXT REFERENCES devices(id),
    ecosystem TEXT NOT NULL DEFAULT 'npm',
    package_name TEXT NOT NULL,
    version TEXT,
    license TEXT,
    direct INTEGER NOT NULL DEFAULT 1,
    details_json TEXT NOT NULL DEFAULT '{}',
    discovered_at TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS cnapp_supply_chain_threats (
    id TEXT PRIMARY KEY NOT NULL,
    dependency_id TEXT REFERENCES cnapp_dependencies(id),
    device_id TEXT REFERENCES devices(id),
    threat_kind TEXT NOT NULL DEFAULT 'typosquat',
    severity TEXT NOT NULL DEFAULT 'medium',
    title TEXT NOT NULL,
    description TEXT,
    status TEXT NOT NULL DEFAULT 'open',
    details_json TEXT NOT NULL DEFAULT '{}',
    detected_at TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS cnapp_sbom_documents (
    id TEXT PRIMARY KEY NOT NULL,
    device_id TEXT REFERENCES devices(id),
    format TEXT NOT NULL DEFAULT 'cyclonedx',
    name TEXT NOT NULL,
    version TEXT,
    source TEXT,
    component_count INTEGER NOT NULL DEFAULT 0,
    details_json TEXT NOT NULL DEFAULT '{}',
    generated_at TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS cnapp_sbom_components (
    id TEXT PRIMARY KEY NOT NULL,
    document_id TEXT NOT NULL REFERENCES cnapp_sbom_documents(id),
    device_id TEXT REFERENCES devices(id),
    name TEXT NOT NULL,
    version TEXT,
    purl TEXT,
    license TEXT,
    kind TEXT NOT NULL DEFAULT 'library',
    details_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS cnapp_vulnerabilities (
    id TEXT PRIMARY KEY NOT NULL,
    cve_id TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT 'medium',
    score REAL,
    title TEXT NOT NULL,
    description TEXT,
    published_at TEXT,
    details_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS cnapp_affected_assets (
    id TEXT PRIMARY KEY NOT NULL,
    vulnerability_id TEXT NOT NULL REFERENCES cnapp_vulnerabilities(id),
    device_id TEXT REFERENCES devices(id),
    asset_kind TEXT NOT NULL DEFAULT 'container',
    asset_ref TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open',
    details_json TEXT NOT NULL DEFAULT '{}',
    detected_at TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS cnapp_remediation_plans (
    id TEXT PRIMARY KEY NOT NULL,
    finding_ref TEXT NOT NULL,
    plan_kind TEXT NOT NULL DEFAULT 'patch',
    status TEXT NOT NULL DEFAULT 'pending',
    title TEXT NOT NULL,
    steps_json TEXT NOT NULL DEFAULT '[]',
    priority TEXT NOT NULL DEFAULT 'medium',
    details_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS cnapp_attack_path_nodes (
    id TEXT PRIMARY KEY NOT NULL,
    path_id TEXT,
    node_kind TEXT NOT NULL DEFAULT 'asset',
    label TEXT NOT NULL,
    entity_ref TEXT,
    details_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS cnapp_attack_path_edges (
    id TEXT PRIMARY KEY NOT NULL,
    path_id TEXT,
    source_node_id TEXT NOT NULL REFERENCES cnapp_attack_path_nodes(id),
    target_node_id TEXT NOT NULL REFERENCES cnapp_attack_path_nodes(id),
    edge_kind TEXT NOT NULL DEFAULT 'exploits',
    label TEXT,
    details_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS cnapp_attack_paths (
    id TEXT PRIMARY KEY NOT NULL,
    device_id TEXT REFERENCES devices(id),
    name TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT 'high',
    status TEXT NOT NULL DEFAULT 'open',
    entry_asset TEXT,
    target_asset TEXT,
    node_count INTEGER NOT NULL DEFAULT 0,
    details_json TEXT NOT NULL DEFAULT '{}',
    discovered_at TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS cnapp_compliance_controls (
    id TEXT PRIMARY KEY NOT NULL,
    framework TEXT NOT NULL DEFAULT 'cis',
    control_id TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    category TEXT,
    enabled INTEGER NOT NULL DEFAULT 1,
    details_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    UNIQUE(framework, control_id)
);

CREATE TABLE IF NOT EXISTS cnapp_compliance_scores (
    id TEXT PRIMARY KEY NOT NULL,
    device_id TEXT REFERENCES devices(id),
    framework TEXT NOT NULL DEFAULT 'cis',
    score REAL NOT NULL DEFAULT 0,
    passing_controls INTEGER NOT NULL DEFAULT 0,
    failing_controls INTEGER NOT NULL DEFAULT 0,
    evaluated_at TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS cnapp_compliance_violations (
    id TEXT PRIMARY KEY NOT NULL,
    control_id TEXT REFERENCES cnapp_compliance_controls(id),
    device_id TEXT REFERENCES devices(id),
    severity TEXT NOT NULL DEFAULT 'medium',
    title TEXT NOT NULL,
    resource_ref TEXT,
    status TEXT NOT NULL DEFAULT 'open',
    details_json TEXT NOT NULL DEFAULT '{}',
    detected_at TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS cnapp_telemetry_snapshots (
    id TEXT PRIMARY KEY NOT NULL,
    device_id TEXT NOT NULL REFERENCES devices(id),
    posture_finding_count INTEGER NOT NULL DEFAULT 0,
    workload_count INTEGER NOT NULL DEFAULT 0,
    k8s_finding_count INTEGER NOT NULL DEFAULT 0,
    container_finding_count INTEGER NOT NULL DEFAULT 0,
    iac_finding_count INTEGER NOT NULL DEFAULT 0,
    secret_finding_count INTEGER NOT NULL DEFAULT 0,
    vulnerability_count INTEGER NOT NULL DEFAULT 0,
    compliance_violation_count INTEGER NOT NULL DEFAULT 0,
    reported_at TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_cnapp_posture_device ON cnapp_posture_findings(device_id);
CREATE INDEX IF NOT EXISTS idx_cnapp_posture_status ON cnapp_posture_findings(status);
CREATE INDEX IF NOT EXISTS idx_cnapp_cloud_resources_device ON cnapp_cloud_resources(device_id);
CREATE INDEX IF NOT EXISTS idx_cnapp_workloads_device ON cnapp_workloads(device_id);
CREATE INDEX IF NOT EXISTS idx_cnapp_k8s_clusters_device ON cnapp_k8s_clusters(device_id);
CREATE INDEX IF NOT EXISTS idx_cnapp_k8s_findings_cluster ON cnapp_k8s_findings(cluster_id);
CREATE INDEX IF NOT EXISTS idx_cnapp_container_images_device ON cnapp_container_images(device_id);
CREATE INDEX IF NOT EXISTS idx_cnapp_iac_scans_device ON cnapp_iac_scans(device_id);
CREATE INDEX IF NOT EXISTS idx_cnapp_secret_findings_device ON cnapp_secret_findings(device_id);
CREATE INDEX IF NOT EXISTS idx_cnapp_dependencies_device ON cnapp_dependencies(device_id);
CREATE INDEX IF NOT EXISTS idx_cnapp_sbom_documents_device ON cnapp_sbom_documents(device_id);
CREATE INDEX IF NOT EXISTS idx_cnapp_vulnerabilities_cve ON cnapp_vulnerabilities(cve_id);
CREATE INDEX IF NOT EXISTS idx_cnapp_attack_paths_device ON cnapp_attack_paths(device_id);
CREATE INDEX IF NOT EXISTS idx_cnapp_compliance_scores_device ON cnapp_compliance_scores(device_id);
CREATE INDEX IF NOT EXISTS idx_cnapp_telemetry_device ON cnapp_telemetry_snapshots(device_id);
