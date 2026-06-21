use database::{models::now_iso, DbError, DbPool};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MixnetNodeRecord {
    pub id: String,
    pub device_id: String,
    pub node_id: String,
    pub gateway_id: String,
    pub country: Option<String>,
    pub latency_ms: Option<i64>,
    pub healthy: bool,
    pub last_seen_at: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MixnetRouteRecord {
    pub id: String,
    pub device_id: String,
    pub route_id: String,
    pub label: String,
    pub hops: Vec<String>,
    pub socks_port: Option<i32>,
    pub cover_traffic_profile: Option<String>,
    pub active: bool,
    pub last_seen_at: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MixnetHealthSnapshot {
    pub id: String,
    pub device_id: String,
    pub mixnet_connected: bool,
    pub stub_mode: bool,
    pub healthy: bool,
    pub selected_node: Option<Value>,
    pub active_route_count: i64,
    pub cover_traffic_profile: Option<String>,
    pub reported_at: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MixnetInventorySummary {
    pub node_count: i64,
    pub route_count: i64,
    pub active_route_count: i64,
    pub devices_reporting: i64,
    pub nodes: Vec<MixnetNodeRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MixnetHealthSummary {
    pub connected_devices: i64,
    pub healthy_devices: i64,
    pub stub_devices: i64,
    pub total_active_routes: i64,
    pub snapshots: Vec<MixnetHealthSnapshot>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MixnetHeartbeatNode {
    pub id: String,
    pub gateway_id: String,
    pub country: Option<String>,
    pub latency_ms: Option<u64>,
    pub healthy: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MixnetHeartbeatRoute {
    pub route_id: String,
    pub label: String,
    pub hops: Vec<String>,
    pub socks_port: Option<u16>,
    pub cover_traffic_profile: Option<String>,
    pub active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MixnetHeartbeat {
    pub mixnet_connected: bool,
    pub stub_mode: bool,
    pub selected_node: Option<MixnetHeartbeatNode>,
    pub active_routes: Vec<MixnetHeartbeatRoute>,
    pub cover_traffic_profile: Option<String>,
    pub reported_at: Option<String>,
}

pub struct MixnetInventoryManager {
    pool: DbPool,
}

impl MixnetInventoryManager {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    pub async fn list_nodes(&self) -> Result<Vec<MixnetNodeRecord>, DbError> {
        let rows = sqlx::query_as::<_, database::models::MixnetNodeRow>(
            "SELECT id, device_id, node_id, gateway_id, country, latency_ms, healthy, last_seen_at, created_at, updated_at
             FROM mixnet_nodes ORDER BY last_seen_at DESC",
        )
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(row_to_node).collect()
    }

    pub async fn list_routes(&self) -> Result<Vec<MixnetRouteRecord>, DbError> {
        let rows = sqlx::query_as::<_, database::models::MixnetRouteRow>(
            "SELECT id, device_id, route_id, label, hops_json, socks_port, cover_traffic_profile, active, last_seen_at, created_at, updated_at
             FROM mixnet_routes ORDER BY last_seen_at DESC",
        )
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(row_to_route).collect()
    }

    pub async fn summary(&self) -> Result<MixnetInventorySummary, DbError> {
        let nodes = self.list_nodes().await?;
        let routes = self.list_routes().await?;
        let active_route_count = routes.iter().filter(|r| r.active).count() as i64;
        let devices_reporting: (i64,) = sqlx::query_as(
            "SELECT COUNT(DISTINCT device_id) FROM mixnet_health_snapshots",
        )
        .fetch_one(&self.pool)
        .await?;

        Ok(MixnetInventorySummary {
            node_count: nodes.len() as i64,
            route_count: routes.len() as i64,
            active_route_count,
            devices_reporting: devices_reporting.0,
            nodes,
        })
    }

    pub async fn ingest_heartbeat(
        &self,
        device_id: &str,
        hb: &MixnetHeartbeat,
    ) -> Result<(), DbError> {
        let now = now_iso();
        let reported_at = hb.reported_at.clone().unwrap_or_else(|| now.clone());

        if let Some(ref node) = hb.selected_node {
            let row_id = Uuid::new_v4().to_string();
            sqlx::query(
                "INSERT INTO mixnet_nodes (id, device_id, node_id, gateway_id, country, latency_ms, healthy, last_seen_at, created_at, updated_at)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                 ON CONFLICT(device_id, node_id) DO UPDATE SET
                   gateway_id = excluded.gateway_id,
                   country = excluded.country,
                   latency_ms = excluded.latency_ms,
                   healthy = excluded.healthy,
                   last_seen_at = excluded.last_seen_at,
                   updated_at = excluded.updated_at",
            )
            .bind(&row_id)
            .bind(device_id)
            .bind(&node.id)
            .bind(&node.gateway_id)
            .bind(&node.country)
            .bind(node.latency_ms.map(|v| v as i64))
            .bind(node.healthy)
            .bind(&reported_at)
            .bind(&now)
            .bind(&now)
            .execute(&self.pool)
            .await?;
        }

        for route in &hb.active_routes {
            let row_id = Uuid::new_v4().to_string();
            let hops_json =
                serde_json::to_string(&route.hops).unwrap_or_else(|_| "[]".into());
            sqlx::query(
                "INSERT INTO mixnet_routes (id, device_id, route_id, label, hops_json, socks_port, cover_traffic_profile, active, last_seen_at, created_at, updated_at)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                 ON CONFLICT(device_id, route_id) DO UPDATE SET
                   label = excluded.label,
                   hops_json = excluded.hops_json,
                   socks_port = excluded.socks_port,
                   cover_traffic_profile = excluded.cover_traffic_profile,
                   active = excluded.active,
                   last_seen_at = excluded.last_seen_at,
                   updated_at = excluded.updated_at",
            )
            .bind(&row_id)
            .bind(device_id)
            .bind(&route.route_id)
            .bind(&route.label)
            .bind(&hops_json)
            .bind(route.socks_port.map(|v| v as i32))
            .bind(&route.cover_traffic_profile)
            .bind(route.active)
            .bind(&reported_at)
            .bind(&now)
            .bind(&now)
            .execute(&self.pool)
            .await?;
        }

        Ok(())
    }
}

pub struct MixnetHealthAggregator {
    pool: DbPool,
}

impl MixnetHealthAggregator {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    pub async fn list_snapshots(&self, limit: Option<i64>) -> Result<Vec<MixnetHealthSnapshot>, DbError> {
        let limit = limit.unwrap_or(50);
        let rows = sqlx::query_as::<_, database::models::MixnetHealthSnapshotRow>(
            "SELECT id, device_id, mixnet_connected, stub_mode, healthy, selected_node_json, active_route_count, cover_traffic_profile, reported_at, created_at
             FROM mixnet_health_snapshots ORDER BY reported_at DESC LIMIT ?",
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(row_to_snapshot).collect()
    }

    pub async fn summary(&self) -> Result<MixnetHealthSummary, DbError> {
        let snapshots = self.list_snapshots(Some(100)).await?;
        let connected_devices = snapshots.iter().filter(|s| s.mixnet_connected).count() as i64;
        let healthy_devices = snapshots.iter().filter(|s| s.healthy).count() as i64;
        let stub_devices = snapshots.iter().filter(|s| s.stub_mode).count() as i64;
        let total_active_routes: i64 = snapshots.iter().map(|s| s.active_route_count).sum();

        Ok(MixnetHealthSummary {
            connected_devices,
            healthy_devices,
            stub_devices,
            total_active_routes,
            snapshots,
        })
    }

    pub async fn ingest(
        &self,
        device_id: &str,
        hb: &MixnetHeartbeat,
    ) -> Result<MixnetHealthSnapshot, DbError> {
        let now = now_iso();
        let reported_at = hb.reported_at.clone().unwrap_or_else(|| now.clone());
        let selected_node_json = hb
            .selected_node
            .as_ref()
            .and_then(|n| serde_json::to_value(n).ok())
            .map(|v| serde_json::to_string(&v).unwrap_or_else(|_| "{}".into()));
        let healthy = hb
            .selected_node
            .as_ref()
            .map(|n| n.healthy)
            .unwrap_or(false);
        let active_route_count = hb.active_routes.iter().filter(|r| r.active).count() as i64;
        let id = Uuid::new_v4().to_string();

        sqlx::query(
            "INSERT INTO mixnet_health_snapshots (id, device_id, mixnet_connected, stub_mode, healthy, selected_node_json, active_route_count, cover_traffic_profile, reported_at, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&id)
        .bind(device_id)
        .bind(hb.mixnet_connected)
        .bind(hb.stub_mode)
        .bind(healthy)
        .bind(&selected_node_json)
        .bind(active_route_count)
        .bind(&hb.cover_traffic_profile)
        .bind(&reported_at)
        .bind(&now)
        .execute(&self.pool)
        .await?;

        Ok(MixnetHealthSnapshot {
            id,
            device_id: device_id.to_string(),
            mixnet_connected: hb.mixnet_connected,
            stub_mode: hb.stub_mode,
            healthy,
            selected_node: selected_node_json
                .as_ref()
                .and_then(|s| serde_json::from_str(s).ok()),
            active_route_count,
            cover_traffic_profile: hb.cover_traffic_profile.clone(),
            reported_at,
            created_at: now,
        })
    }
}

fn row_to_node(row: database::models::MixnetNodeRow) -> Result<MixnetNodeRecord, DbError> {
    Ok(MixnetNodeRecord {
        id: row.id,
        device_id: row.device_id,
        node_id: row.node_id,
        gateway_id: row.gateway_id,
        country: row.country,
        latency_ms: row.latency_ms,
        healthy: row.healthy != 0,
        last_seen_at: row.last_seen_at,
        created_at: row.created_at,
        updated_at: row.updated_at,
    })
}

fn row_to_route(row: database::models::MixnetRouteRow) -> Result<MixnetRouteRecord, DbError> {
    let hops: Vec<String> = serde_json::from_str(&row.hops_json).unwrap_or_default();
    Ok(MixnetRouteRecord {
        id: row.id,
        device_id: row.device_id,
        route_id: row.route_id,
        label: row.label,
        hops,
        socks_port: row.socks_port,
        cover_traffic_profile: row.cover_traffic_profile,
        active: row.active != 0,
        last_seen_at: row.last_seen_at,
        created_at: row.created_at,
        updated_at: row.updated_at,
    })
}

fn row_to_snapshot(
    row: database::models::MixnetHealthSnapshotRow,
) -> Result<MixnetHealthSnapshot, DbError> {
    let selected_node = row
        .selected_node_json
        .as_ref()
        .and_then(|s| serde_json::from_str(s).ok());
    Ok(MixnetHealthSnapshot {
        id: row.id,
        device_id: row.device_id,
        mixnet_connected: row.mixnet_connected != 0,
        stub_mode: row.stub_mode != 0,
        healthy: row.healthy != 0,
        selected_node,
        active_route_count: row.active_route_count,
        cover_traffic_profile: row.cover_traffic_profile,
        reported_at: row.reported_at,
        created_at: row.created_at,
    })
}
