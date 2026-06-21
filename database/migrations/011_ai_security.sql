-- Phase 19 AI Security controller integration

CREATE TABLE IF NOT EXISTS ai_copilot_queries (
    id TEXT PRIMARY KEY NOT NULL,
    device_id TEXT REFERENCES devices(id),
    user_id TEXT,
    session_id TEXT,
    query_text TEXT NOT NULL,
    context_json TEXT NOT NULL DEFAULT '{}',
    status TEXT NOT NULL DEFAULT 'completed',
    details_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ai_copilot_responses (
    id TEXT PRIMARY KEY NOT NULL,
    query_id TEXT NOT NULL REFERENCES ai_copilot_queries(id),
    response_text TEXT NOT NULL,
    model_id TEXT NOT NULL DEFAULT 'wiresentinel-copilot',
    tokens_used INTEGER NOT NULL DEFAULT 0,
    latency_ms INTEGER NOT NULL DEFAULT 0,
    citations_json TEXT NOT NULL DEFAULT '[]',
    details_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ai_investigations (
    id TEXT PRIMARY KEY NOT NULL,
    device_id TEXT REFERENCES devices(id),
    title TEXT NOT NULL,
    description TEXT,
    status TEXT NOT NULL DEFAULT 'open',
    severity TEXT NOT NULL DEFAULT 'medium',
    priority TEXT NOT NULL DEFAULT 'medium',
    owner TEXT,
    source TEXT NOT NULL DEFAULT 'ai',
    tags_json TEXT NOT NULL DEFAULT '[]',
    details_json TEXT NOT NULL DEFAULT '{}',
    opened_at TEXT NOT NULL,
    closed_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ai_investigation_artifacts (
    id TEXT PRIMARY KEY NOT NULL,
    investigation_id TEXT NOT NULL REFERENCES ai_investigations(id),
    artifact_kind TEXT NOT NULL DEFAULT 'log',
    name TEXT NOT NULL,
    uri TEXT,
    hash_sha256 TEXT,
    details_json TEXT NOT NULL DEFAULT '{}',
    collected_at TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ai_investigation_timelines (
    id TEXT PRIMARY KEY NOT NULL,
    investigation_id TEXT NOT NULL REFERENCES ai_investigations(id),
    event_kind TEXT NOT NULL DEFAULT 'note',
    title TEXT NOT NULL,
    description TEXT,
    actor TEXT,
    details_json TEXT NOT NULL DEFAULT '{}',
    occurred_at TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ai_correlated_threats (
    id TEXT PRIMARY KEY NOT NULL,
    device_id TEXT REFERENCES devices(id),
    threat_kind TEXT NOT NULL DEFAULT 'correlation',
    title TEXT NOT NULL,
    description TEXT,
    severity TEXT NOT NULL DEFAULT 'medium',
    status TEXT NOT NULL DEFAULT 'open',
    confidence REAL NOT NULL DEFAULT 0.5,
    source_refs_json TEXT NOT NULL DEFAULT '[]',
    details_json TEXT NOT NULL DEFAULT '{}',
    detected_at TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ai_correlation_links (
    id TEXT PRIMARY KEY NOT NULL,
    threat_id TEXT NOT NULL REFERENCES ai_correlated_threats(id),
    entity_kind TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    link_kind TEXT NOT NULL DEFAULT 'related',
    weight REAL NOT NULL DEFAULT 1.0,
    details_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ai_kg_nodes (
    id TEXT PRIMARY KEY NOT NULL,
    device_id TEXT REFERENCES devices(id),
    node_kind TEXT NOT NULL DEFAULT 'entity',
    label TEXT NOT NULL,
    entity_ref TEXT,
    properties_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ai_kg_edges (
    id TEXT PRIMARY KEY NOT NULL,
    source_node_id TEXT NOT NULL REFERENCES ai_kg_nodes(id),
    target_node_id TEXT NOT NULL REFERENCES ai_kg_nodes(id),
    edge_kind TEXT NOT NULL DEFAULT 'related',
    label TEXT,
    weight REAL NOT NULL DEFAULT 1.0,
    properties_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ai_rag_documents (
    id TEXT PRIMARY KEY NOT NULL,
    device_id TEXT REFERENCES devices(id),
    doc_kind TEXT NOT NULL DEFAULT 'intel',
    title TEXT NOT NULL,
    source TEXT,
    content_hash TEXT,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    indexed_at TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ai_rag_chunks (
    id TEXT PRIMARY KEY NOT NULL,
    document_id TEXT NOT NULL REFERENCES ai_rag_documents(id),
    chunk_index INTEGER NOT NULL DEFAULT 0,
    content TEXT NOT NULL,
    embedding_ref TEXT,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ai_detection_suggestions (
    id TEXT PRIMARY KEY NOT NULL,
    device_id TEXT REFERENCES devices(id),
    investigation_id TEXT REFERENCES ai_investigations(id),
    rule_title TEXT NOT NULL,
    rule_logic TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT 'medium',
    confidence REAL NOT NULL DEFAULT 0.7,
    status TEXT NOT NULL DEFAULT 'suggested',
    mitre_techniques_json TEXT NOT NULL DEFAULT '[]',
    details_json TEXT NOT NULL DEFAULT '{}',
    generated_at TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ai_playbook_suggestions (
    id TEXT PRIMARY KEY NOT NULL,
    device_id TEXT REFERENCES devices(id),
    investigation_id TEXT REFERENCES ai_investigations(id),
    name TEXT NOT NULL,
    playbook_kind TEXT NOT NULL DEFAULT 'response',
    steps_json TEXT NOT NULL DEFAULT '[]',
    triggers_json TEXT NOT NULL DEFAULT '[]',
    status TEXT NOT NULL DEFAULT 'suggested',
    details_json TEXT NOT NULL DEFAULT '{}',
    generated_at TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ai_policy_suggestions (
    id TEXT PRIMARY KEY NOT NULL,
    device_id TEXT REFERENCES devices(id),
    investigation_id TEXT REFERENCES ai_investigations(id),
    policy_kind TEXT NOT NULL DEFAULT 'access',
    title TEXT NOT NULL,
    policy_json TEXT NOT NULL DEFAULT '{}',
    status TEXT NOT NULL DEFAULT 'suggested',
    rationale TEXT,
    details_json TEXT NOT NULL DEFAULT '{}',
    generated_at TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ai_intel_reports (
    id TEXT PRIMARY KEY NOT NULL,
    device_id TEXT REFERENCES devices(id),
    report_kind TEXT NOT NULL DEFAULT 'threat_intel',
    title TEXT NOT NULL,
    summary TEXT,
    content_json TEXT NOT NULL DEFAULT '{}',
    sources_json TEXT NOT NULL DEFAULT '[]',
    published_at TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ai_executive_reports (
    id TEXT PRIMARY KEY NOT NULL,
    report_kind TEXT NOT NULL DEFAULT 'executive',
    title TEXT NOT NULL,
    summary TEXT,
    content_json TEXT NOT NULL DEFAULT '{}',
    period_start TEXT,
    period_end TEXT,
    published_at TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ai_risk_scores (
    id TEXT PRIMARY KEY NOT NULL,
    device_id TEXT REFERENCES devices(id),
    scope_kind TEXT NOT NULL DEFAULT 'organization',
    scope_ref TEXT,
    risk_score INTEGER NOT NULL DEFAULT 50,
    risk_level TEXT NOT NULL DEFAULT 'medium',
    factors_json TEXT NOT NULL DEFAULT '{}',
    evaluated_at TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ai_prompt_audit_log (
    id TEXT PRIMARY KEY NOT NULL,
    user_id TEXT,
    device_id TEXT REFERENCES devices(id),
    prompt_kind TEXT NOT NULL DEFAULT 'copilot',
    prompt_hash TEXT NOT NULL,
    model_id TEXT NOT NULL DEFAULT 'wiresentinel-copilot',
    tokens_in INTEGER NOT NULL DEFAULT 0,
    tokens_out INTEGER NOT NULL DEFAULT 0,
    blocked INTEGER NOT NULL DEFAULT 0,
    reason TEXT,
    details_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ai_telemetry_snapshots (
    id TEXT PRIMARY KEY NOT NULL,
    device_id TEXT NOT NULL REFERENCES devices(id),
    investigation_count INTEGER NOT NULL DEFAULT 0,
    threat_count INTEGER NOT NULL DEFAULT 0,
    suggestion_count INTEGER NOT NULL DEFAULT 0,
    kg_node_count INTEGER NOT NULL DEFAULT 0,
    reported_at TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_ai_copilot_queries_device ON ai_copilot_queries(device_id);
CREATE INDEX IF NOT EXISTS idx_ai_investigations_device ON ai_investigations(device_id);
CREATE INDEX IF NOT EXISTS idx_ai_investigations_status ON ai_investigations(status);
CREATE INDEX IF NOT EXISTS idx_ai_correlated_threats_device ON ai_correlated_threats(device_id);
CREATE INDEX IF NOT EXISTS idx_ai_kg_nodes_device ON ai_kg_nodes(device_id);
CREATE INDEX IF NOT EXISTS idx_ai_detection_suggestions_device ON ai_detection_suggestions(device_id);
CREATE INDEX IF NOT EXISTS idx_ai_playbook_suggestions_device ON ai_playbook_suggestions(device_id);
CREATE INDEX IF NOT EXISTS idx_ai_policy_suggestions_device ON ai_policy_suggestions(device_id);
CREATE INDEX IF NOT EXISTS idx_ai_intel_reports_device ON ai_intel_reports(device_id);
CREATE INDEX IF NOT EXISTS idx_ai_risk_scores_device ON ai_risk_scores(device_id);
CREATE INDEX IF NOT EXISTS idx_ai_telemetry_device ON ai_telemetry_snapshots(device_id);
