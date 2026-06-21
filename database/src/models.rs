use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct UserRow {
    pub id: String,
    pub username: String,
    pub password_hash: String,
    pub role: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct EnrollmentTokenRow {
    pub id: String,
    pub token_hash: String,
    pub label: Option<String>,
    pub created_at: String,
    pub expires_at: Option<String>,
    pub revoked_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct DeviceRow {
    pub id: String,
    pub name: String,
    pub hostname: Option<String>,
    pub os: Option<String>,
    pub agent_version: Option<String>,
    pub enrollment_token_id: Option<String>,
    pub status: String,
    pub last_heartbeat_at: Option<String>,
    pub created_at: String,
    pub metadata: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct PolicyRow {
    pub id: String,
    pub name: String,
    pub scope: String,
    pub scope_target: Option<String>,
    pub content: String,
    pub version: i64,
    pub pushed_at: Option<String>,
    pub revoked_at: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct AuditEventRow {
    pub id: String,
    pub source: String,
    pub actor: Option<String>,
    pub action: String,
    pub resource_type: Option<String>,
    pub resource_id: Option<String>,
    pub details: String,
    pub created_at: String,
}

pub fn now_iso() -> String {
    Utc::now().to_rfc3339()
}

pub fn parse_iso(s: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(s)
        .ok()
        .map(|dt| dt.with_timezone(&Utc))
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct MixnetNodeRow {
    pub id: String,
    pub device_id: String,
    pub node_id: String,
    pub gateway_id: String,
    pub country: Option<String>,
    pub latency_ms: Option<i64>,
    pub healthy: i64,
    pub last_seen_at: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct MixnetRouteRow {
    pub id: String,
    pub device_id: String,
    pub route_id: String,
    pub label: String,
    pub hops_json: String,
    pub socks_port: Option<i32>,
    pub cover_traffic_profile: Option<String>,
    pub active: i64,
    pub last_seen_at: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct FederatedRegistrationRow {
    pub id: String,
    pub cloud_controller_id: String,
    pub tenant_id: String,
    pub federation_token_hash: String,
    pub cloud_base_url: String,
    pub registered_at: String,
    pub outbound_federation_token: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct CloudControllerLinkRow {
    pub id: String,
    pub tenant_id: String,
    pub cloud_base_url: String,
    pub federation_token_hash: String,
    pub registered_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct FederationSyncBundleRow {
    pub id: String,
    pub tenant_id: Option<String>,
    pub bundle_json: String,
    pub pushed_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct MixnetHealthSnapshotRow {
    pub id: String,
    pub device_id: String,
    pub mixnet_connected: i64,
    pub stub_mode: i64,
    pub healthy: i64,
    pub selected_node_json: Option<String>,
    pub active_route_count: i64,
    pub cover_traffic_profile: Option<String>,
    pub reported_at: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct KernelSnapshotRow {
    pub id: String,
    pub device_id: String,
    pub guardian_mode: String,
    pub driver_connected: i64,
    pub lifecycle_state: String,
    pub kill_switch_mode: Option<String>,
    pub stub_mode: i64,
    pub wfp_engine: String,
    pub ndis_enabled: i64,
    pub healthy: i64,
    pub filter_count: i64,
    pub callouts_registered: i64,
    pub transform_profile: Option<String>,
    pub cover_traffic_profile: Option<String>,
    pub telemetry_json: Option<String>,
    pub active_route_count: i64,
    pub reported_at: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct KernelFlowStatRow {
    pub id: String,
    pub device_id: String,
    pub stat_type: String,
    pub flow_id: String,
    pub process_id: Option<i64>,
    pub protocol: Option<i64>,
    pub bytes: i64,
    pub direction: Option<String>,
    pub route_kind: Option<String>,
    pub profile_id: Option<i64>,
    pub label: Option<String>,
    pub active: i64,
    pub last_seen_at: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct AnonymitySnapshotRow {
    pub id: String,
    pub device_id: String,
    pub anonymity_connected: i64,
    pub stub_mode: i64,
    pub healthy: i64,
    pub anonymity_score: i64,
    pub route_entropy: f64,
    pub path_diversity: f64,
    pub cover_traffic_effectiveness: f64,
    pub federation_peer_count: i64,
    pub entropy_bits: f64,
    pub active_route_count: i64,
    pub federation_json: Option<String>,
    pub reported_at: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct AnonymityRouteRow {
    pub id: String,
    pub device_id: String,
    pub route_id: String,
    pub label: String,
    pub hops_json: String,
    pub chain_kind: Option<String>,
    pub entropy_score: Option<f64>,
    pub active: i64,
    pub last_seen_at: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct AnonymityAnalyticsRollupRow {
    pub id: String,
    pub devices_reporting: i64,
    pub avg_anonymity_score: f64,
    pub avg_route_entropy: f64,
    pub avg_path_diversity: f64,
    pub avg_cover_traffic_effectiveness: f64,
    pub federation_peers_total: i64,
    pub avg_entropy_bits: f64,
    pub rollup_json: String,
    pub rolled_up_at: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct ZtnaPolicyRow {
    pub id: String,
    pub name: String,
    pub enabled: i64,
    pub min_trust_level: String,
    pub min_trust_score: i64,
    pub conditions_json: String,
    pub default_action: String,
    pub content_json: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct PublishedResourceRow {
    pub id: String,
    pub name: String,
    pub resource_type: String,
    pub host: String,
    pub port: i64,
    pub path_prefix: Option<String>,
    pub tags_json: String,
    pub published: i64,
    pub access_policy_id: Option<String>,
    pub published_at: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct DeviceTrustRow {
    pub id: String,
    pub device_id: String,
    pub trust_level: String,
    pub trust_score: i64,
    pub posture_json: String,
    pub certificate_fingerprint: Option<String>,
    pub last_evaluated_at: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct ZtnaHeartbeatRow {
    pub id: String,
    pub device_id: String,
    pub identity_connected: i64,
    pub active_provider: Option<String>,
    pub gateway_active: i64,
    pub connector_count: i64,
    pub healthy_connectors: i64,
    pub avg_trust_score: f64,
    pub published_resource_count: i64,
    pub recent_denials: i64,
    pub reported_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct ConnectorRow {
    pub id: String,
    pub device_id: String,
    pub connector_id: String,
    pub name: String,
    pub endpoint: String,
    pub resource_ids_json: String,
    pub healthy: i64,
    pub latency_ms: Option<i64>,
    pub last_seen_at: String,
    pub registered_at: String,
    pub created_at: String,
    pub updated_at: String,
}
