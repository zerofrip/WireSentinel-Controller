-- Phase 17 XDR controller integration

CREATE TABLE IF NOT EXISTS xdr_incidents (
    id TEXT PRIMARY KEY NOT NULL,
    device_id TEXT REFERENCES devices(id),
    title TEXT NOT NULL,
    description TEXT,
    severity TEXT NOT NULL DEFAULT 'medium',
    status TEXT NOT NULL DEFAULT 'open',
    source TEXT NOT NULL DEFAULT 'xdr',
    mitre_techniques_json TEXT NOT NULL DEFAULT '[]',
    details_json TEXT NOT NULL DEFAULT '{}',
    detected_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS xdr_incident_artifacts (
    id TEXT PRIMARY KEY NOT NULL,
    incident_id TEXT NOT NULL REFERENCES xdr_incidents(id),
    artifact_kind TEXT NOT NULL DEFAULT 'file',
    label TEXT NOT NULL,
    value TEXT,
    hash_sha256 TEXT,
    details_json TEXT NOT NULL DEFAULT '{}',
    collected_at TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS xdr_incident_timeline (
    id TEXT PRIMARY KEY NOT NULL,
    incident_id TEXT NOT NULL REFERENCES xdr_incidents(id),
    entry_kind TEXT NOT NULL DEFAULT 'note',
    message TEXT NOT NULL,
    actor TEXT,
    details_json TEXT NOT NULL DEFAULT '{}',
    recorded_at TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS xdr_cases (
    id TEXT PRIMARY KEY NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    status TEXT NOT NULL DEFAULT 'open',
    priority TEXT NOT NULL DEFAULT 'medium',
    assignee TEXT,
    incident_ids_json TEXT NOT NULL DEFAULT '[]',
    details_json TEXT NOT NULL DEFAULT '{}',
    opened_at TEXT NOT NULL,
    closed_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS xdr_case_comments (
    id TEXT PRIMARY KEY NOT NULL,
    case_id TEXT NOT NULL REFERENCES xdr_cases(id),
    author TEXT NOT NULL,
    body TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS xdr_case_evidence (
    id TEXT PRIMARY KEY NOT NULL,
    case_id TEXT NOT NULL REFERENCES xdr_cases(id),
    evidence_kind TEXT NOT NULL DEFAULT 'artifact',
    label TEXT NOT NULL,
    reference TEXT,
    details_json TEXT NOT NULL DEFAULT '{}',
    collected_at TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS xdr_detection_rules (
    id TEXT PRIMARY KEY NOT NULL,
    name TEXT NOT NULL,
    rule_kind TEXT NOT NULL DEFAULT 'sigma',
    enabled INTEGER NOT NULL DEFAULT 1,
    severity TEXT NOT NULL DEFAULT 'medium',
    query_json TEXT NOT NULL DEFAULT '{}',
    mitre_techniques_json TEXT NOT NULL DEFAULT '[]',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS xdr_detections (
    id TEXT PRIMARY KEY NOT NULL,
    device_id TEXT REFERENCES devices(id),
    rule_id TEXT REFERENCES xdr_detection_rules(id),
    title TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT 'medium',
    status TEXT NOT NULL DEFAULT 'new',
    confidence REAL NOT NULL DEFAULT 0.5,
    details_json TEXT NOT NULL DEFAULT '{}',
    detected_at TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS xdr_detection_matches (
    id TEXT PRIMARY KEY NOT NULL,
    detection_id TEXT NOT NULL REFERENCES xdr_detections(id),
    rule_id TEXT REFERENCES xdr_detection_rules(id),
    match_kind TEXT NOT NULL DEFAULT 'rule',
    matched_value TEXT,
    details_json TEXT NOT NULL DEFAULT '{}',
    matched_at TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS xdr_hunts (
    id TEXT PRIMARY KEY NOT NULL,
    name TEXT NOT NULL,
    description TEXT,
    query_kind TEXT NOT NULL DEFAULT 'kql',
    query_text TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'draft',
    owner TEXT,
    details_json TEXT NOT NULL DEFAULT '{}',
    started_at TEXT,
    completed_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS xdr_hunt_results (
    id TEXT PRIMARY KEY NOT NULL,
    hunt_id TEXT NOT NULL REFERENCES xdr_hunts(id),
    result_kind TEXT NOT NULL DEFAULT 'finding',
    title TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT 'medium',
    details_json TEXT NOT NULL DEFAULT '{}',
    found_at TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS xdr_playbooks (
    id TEXT PRIMARY KEY NOT NULL,
    name TEXT NOT NULL,
    playbook_kind TEXT NOT NULL DEFAULT 'response',
    enabled INTEGER NOT NULL DEFAULT 1,
    steps_json TEXT NOT NULL DEFAULT '[]',
    triggers_json TEXT NOT NULL DEFAULT '[]',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS xdr_playbook_executions (
    id TEXT PRIMARY KEY NOT NULL,
    playbook_id TEXT NOT NULL REFERENCES xdr_playbooks(id),
    device_id TEXT REFERENCES devices(id),
    status TEXT NOT NULL DEFAULT 'pending',
    trigger_source TEXT,
    result_json TEXT NOT NULL DEFAULT '{}',
    started_at TEXT NOT NULL,
    completed_at TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS xdr_attack_graph_nodes (
    id TEXT PRIMARY KEY NOT NULL,
    incident_id TEXT REFERENCES xdr_incidents(id),
    node_kind TEXT NOT NULL DEFAULT 'host',
    label TEXT NOT NULL,
    entity_id TEXT,
    details_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS xdr_attack_graph_edges (
    id TEXT PRIMARY KEY NOT NULL,
    incident_id TEXT REFERENCES xdr_incidents(id),
    source_node_id TEXT NOT NULL REFERENCES xdr_attack_graph_nodes(id),
    target_node_id TEXT NOT NULL REFERENCES xdr_attack_graph_nodes(id),
    edge_kind TEXT NOT NULL DEFAULT 'communicates',
    label TEXT,
    details_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS xdr_mitre_techniques (
    id TEXT PRIMARY KEY NOT NULL,
    technique_id TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    tactic TEXT NOT NULL,
    description TEXT,
    url TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS xdr_mitre_mappings (
    id TEXT PRIMARY KEY NOT NULL,
    detection_rule_id TEXT REFERENCES xdr_detection_rules(id),
    technique_id TEXT NOT NULL REFERENCES xdr_mitre_techniques(technique_id),
    confidence REAL NOT NULL DEFAULT 1.0,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS xdr_response_actions (
    id TEXT PRIMARY KEY NOT NULL,
    device_id TEXT REFERENCES devices(id),
    incident_id TEXT REFERENCES xdr_incidents(id),
    action_kind TEXT NOT NULL DEFAULT 'isolate',
    status TEXT NOT NULL DEFAULT 'pending',
    requested_by TEXT,
    parameters_json TEXT NOT NULL DEFAULT '{}',
    result_json TEXT NOT NULL DEFAULT '{}',
    requested_at TEXT NOT NULL,
    completed_at TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS xdr_edr_events (
    id TEXT PRIMARY KEY NOT NULL,
    device_id TEXT NOT NULL REFERENCES devices(id),
    event_kind TEXT NOT NULL DEFAULT 'process',
    process_name TEXT,
    process_id INTEGER,
    parent_process_id INTEGER,
    user_name TEXT,
    file_path TEXT,
    command_line TEXT,
    hash_sha256 TEXT,
    severity TEXT NOT NULL DEFAULT 'info',
    details_json TEXT NOT NULL DEFAULT '{}',
    observed_at TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS xdr_ndr_events (
    id TEXT PRIMARY KEY NOT NULL,
    device_id TEXT NOT NULL REFERENCES devices(id),
    event_kind TEXT NOT NULL DEFAULT 'flow',
    src_ip TEXT,
    dst_ip TEXT,
    src_port INTEGER,
    dst_port INTEGER,
    protocol TEXT,
    bytes INTEGER,
    severity TEXT NOT NULL DEFAULT 'info',
    details_json TEXT NOT NULL DEFAULT '{}',
    observed_at TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS xdr_itdr_threats (
    id TEXT PRIMARY KEY NOT NULL,
    device_id TEXT REFERENCES devices(id),
    threat_kind TEXT NOT NULL DEFAULT 'credential',
    user_id TEXT,
    identity_provider TEXT,
    severity TEXT NOT NULL DEFAULT 'medium',
    title TEXT NOT NULL,
    description TEXT,
    details_json TEXT NOT NULL DEFAULT '{}',
    detected_at TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS xdr_telemetry_snapshots (
    id TEXT PRIMARY KEY NOT NULL,
    device_id TEXT NOT NULL REFERENCES devices(id),
    edr_event_count INTEGER NOT NULL DEFAULT 0,
    ndr_event_count INTEGER NOT NULL DEFAULT 0,
    itdr_threat_count INTEGER NOT NULL DEFAULT 0,
    detection_count INTEGER NOT NULL DEFAULT 0,
    open_incident_count INTEGER NOT NULL DEFAULT 0,
    reported_at TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_xdr_incidents_device ON xdr_incidents(device_id);
CREATE INDEX IF NOT EXISTS idx_xdr_incidents_status ON xdr_incidents(status);
CREATE INDEX IF NOT EXISTS idx_xdr_cases_status ON xdr_cases(status);
CREATE INDEX IF NOT EXISTS idx_xdr_detections_device ON xdr_detections(device_id);
CREATE INDEX IF NOT EXISTS idx_xdr_hunts_status ON xdr_hunts(status);
CREATE INDEX IF NOT EXISTS idx_xdr_edr_device ON xdr_edr_events(device_id);
CREATE INDEX IF NOT EXISTS idx_xdr_ndr_device ON xdr_ndr_events(device_id);
CREATE INDEX IF NOT EXISTS idx_xdr_telemetry_device ON xdr_telemetry_snapshots(device_id);
